# AGENTS.md

## Cursor Cloud specific instructions

This repo is a single, self-contained **TCP/IP stack emulator written in C** (companion code for a Udemy course). It emulates a multi-node topology of routers/switches inside one process and exposes an interactive CLI. There is no database, no web server, and no external services; the UDP sockets in `comm.c` are purely intra-process (each node binds a loopback port starting at `40000`).

### Build / lint / run

- Build everything from the repo root with `make`. It recurses into `CommandParser/` to build the static lib `libcli.a`, then links `test.exe` and `pkt_gen.exe`. See `Makefile`.
- Toolchain (`gcc`, `make`, `ar`) is preinstalled in the base image; there is no package manager and no dependencies to install.
- Clean with `make clean`; use `make cleanall` to also clean `CommandParser/`.
- There is **no dedicated linter**. "Lint" here is just compiler warnings. The build emits many benign warnings (e.g. `-Wenum-int-mismatch`, `strncpy` truncation) from `CommandParser`; these are expected and do not fail the build.
- On ARM hosts use `make -f MakefileARM` (needs `arm-linux-gnueabi-gcc`); on the default x86 image use the normal `Makefile`.

### Running the app (interactive CLI)

- Run `./test.exe`. It builds the default `build_square_topo()` (nodes `R1`–`R4`) and drops into an interactive REPL prompt `tcp-ip-project>`.
- The REPL reads from stdin. When stdin closes (e.g. piping commands), it prints `error in reading from stdin` and exits — this is normal EOF behavior, not a crash.
- Useful CLI commands (registered in `nwcli.c`): `show topology`, `show node <name> arp|mac|rt`, `run node <name> resolve-arp <ip>`, `run node <name> ping <ip>`, `config node <name> interface ...`, `config node <name> route ...`.

### Testing gotchas

- There is no automated test suite. Validate changes by driving the CLI.
- Packet delivery between nodes runs on background threads over loopback UDP, so it is **asynchronous**. When scripting commands via a pipe, insert short `sleep`s (≈1–2s) between `resolve-arp`/`ping` and reading results, otherwise the process may hit EOF before the reply is processed. Example end-to-end check:
  ```bash
  { printf 'run node R1 resolve-arp 10.1.1.2\n'; sleep 1; \
    printf 'run node R1 ping 10.1.1.2\n'; sleep 2; } | ./test.exe
  ```
  A successful run prints `IP Address : 10.1.1.2, ping success`.
