# Security Policy

## Supported Versions

litecast is developed on a rolling `master` branch. The latest commit on
`master` is the only supported version. Releases published on the [release
page] are supported until the next release supersedes them; older releases
receive no security fixes.

Report security issues in current versions. There are no security patches
for versions that have been superseded.

## Reporting a Vulnerability

If you find a vulnerability, do **not** open a public issue. Report it
privately by email to:

**tiagoapimenta@gmail.com**

Please include:

- a description of the vulnerability and why it is exploitable,
- the affected version (commit hash or tag),
- a minimal reproduction (command line, media input, network setup),
- your suggested fix, if you have one.

You should receive an acknowledgement within 72 hours. After the issue is
fixed, you will be offered credit in the release notes unless you prefer to
stay anonymous.

## Scope

In scope:

- The C source in this repository: CLI parsing, mDNS/DNS-SD discovery
  handling, Cast V2 protocol (de)framing, embedded HTTP server, buffer/cache
  management, `--cache-to-fs` spool handling, and all memory management.
- Command execution under `--command` and file opening in file mode.

Out of scope (owned by third parties, report to their owners):

- Chromecast/Google firmware and Google Cast protocol servers.
- The behavior of media players, encoders, or other programs you pipe into
  litecast.

## Security Model and Considerations

litecast runs on the local network and trusts it to a degree. Understand the
following before using it on anything other than your home network:

- **Plain HTTP media path.** The control channel speaks Cast V2 (TLS on
  modern firmware), but the media stream itself is served over unencrypted
  HTTP from the embedded server and can be observed by anyone on the same
  network. Do not cast content you consider private on an untrusted network.
- **mDNS announcements.** Discovery relies on multicast DNS; device presence
  and service records are visible to any host on the local link.
- **Trusted device.** litecast connects to the first Chromecast it
  discovers and serves the stream to it with no further authentication.
- **`--cache-to-fs` spool.** The spool file is created in the system temp
  directory with `mkstemp`, opened, and immediately unlinked, so it exists
  only as a dangling descriptor and is not visible or writable on the
  filesystem by other processes.
- **Command mode.** `--command` executes a program with the arguments you
  provide; arguments are passed directly (no shell is involved), but you are
  responsible for trusting the command itself.

## Good Practices

- Build from source with `make` (or the released static binaries).
- Run litecast only on networks you control.
- Do not pipe the output of untrusted or unvetted commands into litecast.
- Keep the system GNU/Linux toolchain up to date for translation-unit-level
  hardening (PIE, RELRO, stack protector) at distro level.