#!/usr/bin/env python3
"""Optional end-to-end integration test (NOT part of the quality gate).

Drives the real `bin/litecast` binary against a fake Cast device on the same
host:

  * a UDP responder answers the mDNS browse for `_googlecast._tcp.local`,
    advertising a device at 127.0.0.1:8009;
  * a TCP listener on 127.0.0.1:8009 speaks the minimal Cast V2 control plane
    (CONNECT / GET_STATUS -> RECEIVER_STATUS -> LOAD);
  * on LOAD the fake device issues an HTTP GET to litecast's `contentId` and
    pulls the whole body.

The binary is expected to exit 0 on its own (natural end: source EOF, all
pulls drained, at least one served). The script asserts the control frames it
received and that the HTTP body exactly equals the source file.

Run after `make all`:
    python3 tests/integration_test.py
"""

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile

CAST_PORT = 8009
MCAST_GROUP = "224.0.0.251"
MCAST_PORT = 5353

NS_CONN = "urn:x-cast:com.google.cast.tp.connection"
NS_RX = "urn:x-cast:com.google.cast.receiver"
NS_MEDIA = "urn:x-cast:com.google.cast.media"

HDR = "=="


def die(msg):
    sys.stderr.write(HDR + " FAIL " + msg + "\n")
    sys.exit(1)


def qname(name):
    """Encode a dotted name as a length-prefixed DNS name (no compression)."""
    out = bytearray()
    for label in name.rstrip(".").split("."):
        out.append(len(label))
        out.extend(label.encode())
    out.append(0)
    return bytes(out)


def rrs(name_bytes, rtype, rclass, ttl, rdata):
    return name_bytes + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def build_mdns_response():
    """PTR answer + SRV/A/TXT additional records for a device at :8009."""
    instance = "tv-fake._googlecast._tcp.local."
    svc = "_googlecast._tcp.local."
    inst_q = qname(instance)
    svc_q = qname(svc)

    ptr_rdata = inst_q                      # PTR rdata -> instance name
    srv_rdata = struct.pack(">HHH", 0, 0, CAST_PORT) + inst_q
    a_rdata = socket.inet_aton("127.0.0.1")
    txt_rdata = bytes([4]) + b"fn=fake" + bytes([4]) + b"id=fake123" + bytes([5]) + b"md=Fake"

    # CACHE_FLUSH set (class 0x8001) on the additional records, as live
    # devices announce. The low 15 bits still read class IN (1).
    answer = rrs(svc_q, 12, 0x0001, 120, ptr_rdata)
    additional = (
        rrs(inst_q, 33, 0x8001, 120, srv_rdata)
        + rrs(inst_q, 1, 0x8001, 120, a_rdata)
        + rrs(inst_q, 16, 0x8001, 4500, txt_rdata)
    )

    hdr = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 3)
    return hdr + answer + additional


def proto_frame(source, dest, ns, json_payload):
    """Encode a Cast V2 frame: 4-byte big-endian length + protobuf payload."""
    pb = bytearray()
    pb += b"\x08\x00"                       # field 1: protocol_version = 0
    pb += b"\x12" + bytes([len(source)]) + source.encode()
    pb += b"\x1a" + bytes([len(dest)]) + dest.encode()
    pb += b"\x22" + bytes([len(ns)]) + ns.encode()
    pb += b"\x28\x00"                       # field 5: payload_type = 0 (STRING)
    pb += b"\x32" + bytes([len(json_payload)]) + json_payload.encode()
    return struct.pack(">I", len(pb)) + bytes(pb)


def recv_frame(sock):
    """Read one full Cast frame; returns (source, ns, payload) or None on EOF."""
    hdr = sock.recv(4)
    if len(hdr) == 0:
        return None
    if len(hdr) != 4:
        die("malformed frame prefix")
    (n,) = struct.unpack(">I", hdr)
    if n < 1 or n > 131072:
        die("bad frame length %d" % n)
    body = b""
    while len(body) < n:
        chunk = sock.recv(n - len(body))
        if not chunk:
            die("truncated frame body")
        body += chunk
    return parse_proto(body)


def parse_proto(body):
    """Decode source_id (field 2), namespace (field 4) and JSON payload (field 6)."""
    source = ""
    ns = ""
    payload = ""
    i = 0
    while i < len(body):
        tag, i = read_varint(body, i)
        if tag == 0:
            break
        field, wt = tag >> 3, tag & 7
        if wt == 2:
            ln, i = read_varint(body, i)
            val = body[i:i + ln]
            i += ln
            if field == 2:
                source = val.decode()
            elif field == 4:
                ns = val.decode()
            elif field == 6:
                payload = val.decode()
        elif wt == 0:
            _, i = read_varint(body, i)     # varint value
        elif wt == 1:
            i += 8                          # fixed64
        elif wt == 5:
            i += 4                          # fixed32
        else:
            die("bad wire type %d" % wt)
    return source, ns, payload


def read_varint(b, i):
    acc = 0
    shift = 0
    while i < len(b):
        byte = b[i]
        i += 1
        acc |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return acc, i
        shift += 7
    die("unterminated varint")


def parse_json(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError) as e:
        die("device got non-JSON payload %r: %s" % (text, e))


def http_pull(content_id, expected):
    """GET the stream, return the full body bytes (reads until EOF)."""
    # contentId is "http://127.0.0.1:<port>/stream".
    url = content_id
    if not url.startswith("http://"):
        die("unexpected contentId: %r" % url)
    rest = url[len("http://"):]
    hostport, _, path = rest.partition("/")
    host, _, port = hostport.rpartition(":")
    if path == "":
        path = "/stream"
    else:
        path = "/" + path
    s = socket.create_connection((host, int(port)))
    s.settimeout(20)
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, hostport)).encode()
    s.sendall(req)
    data = b""
    buf = bytearray()
    in_body = False
    while True:
        chunk = s.recv(8192)
        if not chunk:
            break
        if not in_body:
            buf += chunk
            sep = buf.find(b"\r\n\r\n")
            if sep < 0:
                continue
            data += bytes(buf[sep + 4:])     # body after the header terminator
            buf = bytearray()
            in_body = True
        else:
            data += chunk
    s.close()
    if data != expected:
        die("HTTP body mismatch: got %d bytes, want %d" % (len(data), len(expected)))
    return data


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("usage: python3 tests/integration_test.py")
        return 0
    bindir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin")
    binary = os.path.join(bindir, "litecast")
    if not os.path.exists(binary):
        die("binary %s missing -- run 'make all' first" % binary)

    # Source file with a distinctive payload.
    src = tempfile.NamedTemporaryFile(mode="wb", suffix=".mp4", delete=False)
    source_bytes = b"hello-integration-stream-0123456789-\xff\x00\x7f" * 64
    src.write(source_bytes)
    src.close()

    try:
        # --- fake device: mDNS responder + control-plane TCP listener ---
        mdns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        mdns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            mdns.bind((MCAST_GROUP, MCAST_PORT))
        except OSError as e:
            print(HDR + " SKIP mDNS bind: %s (multicast unavailable?)" % e)
            return 1
        mdns.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            struct.pack("4s4s", socket.inet_aton(MCAST_GROUP), socket.inet_aton("0.0.0.0")),
        )
        mdns.settimeout(20)

        ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctrl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            ctrl.bind(("127.0.0.1", CAST_PORT))
        except OSError as e:
            print(HDR + " SKIP port %d in use: %s" % (CAST_PORT, e))
            mdns.close()
            return 1
        ctrl.listen(1)
        ctrl.settimeout(30)

        # --- start the real binary ---
        env = dict(os.environ)
        env["LITECAST_MDNS_MS"] = "4000"
        proc = subprocess.Popen(
            [binary, src.name],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # --- answer the mDNS browse query ---
        answer = build_mdns_response()
        answered = False
        while not answered:
            try:
                data, peer = mdns.recvfrom(4096)
            except socket.timeout:
                break
            # A browse query carries QDCOUNT>=1; answer only the service browse.
            if len(data) >= 12 and struct.unpack(">H", data[4:6])[0] >= 1:
                mdns.sendto(answer, peer)   # unicast reply (RFC 6762)
                answered = True
        if not answered:
            proc.kill()
            mdns.close()
            ctrl.close()
            die("no mDNS browse query received from litecast")

        # --- accept the control connection and drive the protocol ---
        sock = None
        try:
            sock, _ = ctrl.accept()
            sock.settimeout(20)

            src_id = None           # litecast's per-session sender id
            sent_connect = sent_load = False
            done = False
            while not done:
                frame = recv_frame(sock)
                if frame is None:
                    break
                src_id, ns, payload = frame
                obj = parse_json(payload)
                got = obj.get("type", "")

                if ns == NS_CONN and got == "CONNECT":
                    sent_connect = True
                    # source_id is the protobuf field 2, not a JSON key.
                elif ns == NS_RX and got == "GET_STATUS":
                    # Reply back to litecast's source id; requestId echoes.
                    sock.sendall(proto_frame("receiver-0", src_id, NS_RX,
                                             '{"type":"RECEIVER_STATUS","sessionId":"session-42",'
                                             '"requestId":%d}' % obj["requestId"]))
                elif ns == NS_MEDIA and got == "LOAD":
                    sent_load = True
                    sid = obj["sessionId"]
                    cid = obj["contentId"]
                    if sid != "session-42":
                        die("LOAD carried wrong sessionId: %s" % sid)
                    # Reply LOADED, then pull the stream the way a receiver would.
                    sock.sendall(proto_frame("receiver-0", src_id, NS_MEDIA,
                                             '{"type":"LOADED","sessionId":"%s"}' % sid))
                    http_pull(cid, source_bytes)
                    done = True
                elif ns == "urn:x-cast:com.google.cast.tp.heartbeat" and got == "PING":
                    sock.sendall(proto_frame("receiver-0", src_id,
                                             "urn:x-cast:com.google.cast.tp.heartbeat",
                                             '{"type":"PONG"}'))
            if not sent_connect or not sent_load:
                pass                # reported below after the child is reaped
        finally:
            if sock is not None:
                sock.close()
            ctrl.close()
            mdns.close()
            # The binary should exit 0 on its own once the pull is fully
            # drained (natural end). Give it a short grace, then kill so a
            # hanging child cannot leak.
            try:
                rc = proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                rc = proc.returncode
            if rc != 0:
                die("binary exited %d (expected natural 0)" % rc)

        if not sent_connect:
            die("device never saw the CONNECT frame")
        if not sent_load:
            die("device never saw the LOAD frame")
        print(HDR + " OK mDNS discovered device, handshake, LOAD, and %d-byte stream pull" % len(source_bytes))
    finally:
        os.unlink(src.name)


if __name__ == "__main__":
    sys.exit(main())