# MWEmu local patch

`mwemu-pack-support.patch` is the diff this project applies to MWEmu 1.0.1
(Apache-2.0) before building the engine that ships in the sandbox pack. Apply it
to a clean checkout of the tag, then `cargo build --release`:

    git clone --branch v1.0.1 https://github.com/mwemuorg/mwemu
    git -C mwemu apply /path/to/mwemu-pack-support.patch
    cargo build --release --manifest-path mwemu/Cargo.toml

What it adds, and why each one exists:

* `--username`, `--hostname`, `--domain`: the emulated identity, including a
  `domain` field in Config so `USERDOMAIN` is not the computer name.
* `--endpoint`: the flag and its code already existed; the argument was
  commented out of the command line, so the network emulation could not be
  reached.
* `--events-json <PATH>`: one JSON object per API call, appended at the ABI
  boundary in `api/windows/common/trace.rs`. The text trace changes shape with
  verbosity; this is the structure the pack reads, and it is why the pack no
  longer has to parse `** 1000> ...` lines for the common case.
* `--registry <PATH>`: `Registry::load_snapshot` reads `key|name|type|data`
  lines into the emulated registry store. This is a seed, not a hive parser:
  the store stays synthetic and nothing touches the host registry.

The patch stays small on purpose. Everything else the sandbox needs -- child
follow, file_root layout, identity defaults, event consumption -- is in the pack
and needs no engine change.
