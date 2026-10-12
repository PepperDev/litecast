# litecast

A small streaming/cast application that streams local media files, or the
output of an arbitrary command, to a Chromecast (Google Cast) device on the
same network.

It is written in `C99` and built with a plain `Makefile` — no cmake, no
meson, no external dependency libraries, no GUI, no tray icon, no screen
capture. Just files and command output, streamed to the TV.

## Features

- Discovers Chromecast devices on the local network via mDNS/DNS-SD.
- Streams one or more local files; multiple files are concatenated and
  streamed one after another, `cat`-style.
- Streams the output of an arbitrary command through a pipe (`--command`).
- Configurable in-memory buffer (`--cache`): fixed size (`K`/`M`/`G`) or
  percentage, defaulting to `64M`.
- Optional spooling of command output to a dangling temp file
  (`--cache-to-fs`) so the stream can be seeked later.
- Target device selection by friendly name (`--device`), with wildcard
  matching and automatic fallback to the first discovered device.
- No validation that the stream is a valid video — what you feed it is what
  the device gets.
- No runtime dependencies beyond the C standard library.

## Requirements

- Linux.
- A C99 compiler and `make` (musl-gcc or gcc).
- A Chromecast, Chromecast Audio, Google Home/Nest, or any Google Cast
  receiver reachable on the same network.
- For `--command`: any program that writes media to its standard output
  (e.g. `ffmpeg` transcoding to a streamable pipe).

## Build

```sh
make         # build bin/litecast (static, no warnings)
make install # install to /usr/local/bin + man page (make install PREFIX=... to override)
make lint    # format + cppcheck + lizard + loc check
make test    # unit tests
make coverage# tests + merged 80% line coverage gate
make report  # full quality gate: lint + coverage + build
```

## Usage

```
litecast [-b SIZE|--cache SIZE] [-s|--cache-to-fs] [-d NAME|--device NAME]
         [-n|--no-arbitrary-range]
         (-f|--file | -c|--command) [--] <FILES...>|<command-and-args...>
```

`--file`/`-f` and `--command`/`-c` are mutually exclusive. If neither is
given, file mode is assumed. Everything after the last option is the operand
list: the files to cast, or — when `--command` is given — the command
followed by its arguments. `--` terminates option parsing and makes the
remainder positional, so it can be used to cast files whose names begin with
`-`, or to separate a `--command` from arguments that themselves begin with
`-`.

### Options

`--cache SIZE` / `-b SIZE`
: Size of the in-memory data buffer used while casting. Accepts a `K`, `M`
  or `G` suffix (upper- or lower-case), or a trailing `%` for a percentage.
  Defaults to `64M`. The minimum is one page. A percentage can never exceed
  `100%`.

  - **File mode** (`--file`, the default):
    - A plain size gives a fixed-capacity buffer that holds that many bytes
      of the file being cast.
    - A percentage targets that fraction of the file's size. The size is
      obtained with `stat(2)` when a trustworthy size can be computed
      (regular files). When it cannot — pipes, special devices, virtual
      files — the program falls back to dynamic allocation.
  - **Command mode** (`--command`):
    - The command's output arrives through a pipe whose final length is
      unknown, so the buffer is always allocated dynamically: it starts at
      one page and grows as data arrives.
    - With a plain size, the buffer grows toward that size.
    - With a percentage, the target is recomputed from a running counter of
      how much output has been received so far (i.e. the target is that
      percentage of the bytes received), so the buffer tracks the stream. At
      `100%` the buffer simply grows as bytes are received.

`--cache-to-fs` / `-s`
: Spools the casted data to a temporary file. Only meaningful in
  `--command` mode; in file mode it is ignored. A temporary file is created,
  opened, and immediately unlinked so it exists only as a dangling file
  descriptor. 100% of the pipeline output is always written to it as it
  arrives, regardless of `--cache`; the in-memory buffer still follows the
  `--cache` rule. This makes the stream seekable later.

`--device NAME` / `-d NAME`
: Selects the cast target by friendly name. Matching is case-insensitive
  and accepts `*` as the only wildcard. If the named device does not appear
  within the discovery window, a substring match (`*NAME*`) is tried; if
  that also fails, the first discovered device is used. Without `--device`,
  the first discovered device is always the target.

`--no-arbitrary-range` / `-n`
: Compatibility escape hatch. While the stream length is unknown (a command
  that has not finished), the server normally closes an open-ended
  `Range: bytes=N-` by choosing its own end and answers `206` with a
  `Content-Range` whose complete-length is `*` — at the amount produced so
  far, or at one byte when the producer has not yet reached the requested
  position, in which case the reply waits for that byte. With this flag the
  server never invents an end: such a request is answered `200` from byte 0
  (the whole stream is replayed from the beginning), the way it was before.
  Use it for a receiver that stops early on a short partial reply. It has no
  effect in file mode, where the size is known up front.

`--file` / `-f`
: Cast files. This is the default mode; the operands are a list of paths.
  With more than one file the streams are concatenated and played one after
  another, `cat`-style.

`--command` / `-c`
: Cast the standard output of a command. The operands are the command and
  its arguments; it is executed and its stdout is piped to the device.

`--`
: End of options; everything after it is treated as operands.

`-h`, `--help`
: Print usage and exit.

`-V`, `--version`
: Print version and exit.

### Examples

Cast a single file (file mode is the default):

```sh
litecast movie.mp4
```

Cast several files, one after the other:

```sh
litecast episode1.mkv episode2.mkv episode3.mkv
```

Cast a file with a `-`-prefixed name using `--`:

```sh
litecast -- --named-file.mp4
```

Stream the output of a command (e.g. `ffmpeg` transcode on the fly):

```sh
litecast --command ffmpeg -re -i input.mkv -f mpegts -
```

Same, with an explicit separator before the command:

```sh
litecast --command -- ffmpeg -re -i input.mkv -f mpegts -
```

Spool the command output to a seekable temp file with a percentage-sized
in-memory buffer:

```sh
litecast -s -b 50% -c ffmpeg -re -i input.mkv -f mpegts -
```

Cast to a specific device by name (falling back to the first device found):

```sh
litecast --device "Living Room" movie.mp4
```

With `--device` the program casts to the matching device; without it, the
first Chromecast it discovers is used.

## How it works

1. **Discover** — litecast browses the local network with mDNS/DNS-SD for the
   `_googlecast._tcp.local` service, assembling a list of Cast devices from
   their TXT records (friendly name, UUID, model, running app).
2. **Connect** — it opens a control connection to the chosen device on
   TCP port 8009 using Cast V2 framing (a big-endian 4-byte length prefix
   followed by a protobuf `CastMessage`). Recent firmware negotiates TLS up
   front; older devices use plaintext.
3. **Handshake** — it sends `CONNECT` on the connection namespace and keeps
   the control channel alive with periodic `PING`/`PONG` heartbeats.
4. **Serve** — an embedded HTTP server is started on the local interface and
   bound to an ephemeral port. litecast asks the default media receiver for
   a session (`GET_STATUS`) and then loads it (`LOAD`) with the local stream
   URL as `contentId`.
5. **Stream** — the device pulls `http://<local-ip>:<port>/stream`. The HTTP
   handler feeds it from the in-memory buffer, applying the `--cache` rules,
   and from the `--cache-to-fs` spool when present.

Only the minimum needed for casting is implemented: discovery, one control
session, and one embedded HTTP stream.

## Limitations

- No codec/container validation — garbage in, garbage out.
- While the control channel speaks the Cast V2 protocol, the media is
  streamed over plain HTTP on the local network; transport encryption is not
  a goal of this project.
- Device selection is name-based only (`--device`); there is no list
  browsing, volume, pause/play, or app control yet.
- A buffer smaller than the whole stream is non-seekable unless
  `--cache-to-fs` (command mode) is used.

## Documentation

- [AGENTS.md](AGENTS.md) — rules and workflow for AI agents and maintainers.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute, code standards,
  testing and the quality gate.
- [SECURITY.md](SECURITY.md) — security policy and reporting.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards.
- `man/litecast.1` — the CLI manual page.

## License

MIT. See [LICENSE](LICENSE).