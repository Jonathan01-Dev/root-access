# Archipel Architecture

## Modules

- `src/network/`
  - multicast discovery (HELLO/PEER_LIST)
  - TCP listener and packet dispatch
  - peer table persistence
- `src/crypto/`
  - identity generation/loading
- `src/transfer/`
  - manifest generation
  - chunk scheduling and download manager
- `src/messaging/`
  - optional Gemini integration (disable with `--no-ai`)
- `src/main.py`
  - interactive CLI entrypoint

## Data flow

```text
[Node A] -- HELLO(UDP multicast) --> [LAN group]
[Node B] -- HELLO(UDP multicast) --> [LAN group]

[Node A] <----- TCP unicast ------> [Node B]
           MSG / MANIFEST / CHUNK_REQ / CHUNK_DATA
```

## Security notes

- Private keys are local files, never committed.
- Runtime state (`peer_table*.json`, `*.part`) is ignored in Git.
- AI endpoint is isolated and optional.

