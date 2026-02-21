# TIL (Today I Learned)

## Singapore NRIC/FIN Checksum

Singapore NRIC/FIN checksum is one of the more interesting national ID validators — it uses three completely different check-letter lookup tables depending on the prefix character:

- **S/T** (citizens): `JZIHGFEDCBA` — S has offset 0, T has offset 4 (distinguishes pre-2000 vs post-2000)
- **F/G** (foreigners): `XWUTRQPNMLK` — same offset split as S/T
- **M** (foreigners post-2022): `KLJNPQRTUWX` with a rotation (`10 - index`) before lookup, plus offset 3

This makes it much harder to forge than simpler mod-N checksums since you need to know the correct table for each prefix.

## `cargo build` vs `cargo install` binary paths

`cargo build` places the binary in `target/debug/anon` (or `target/release/anon`), but the shell resolves bare `anon` to whatever's on `$PATH` — typically a previously installed copy at `~/.local/bin/anon` or `~/.cargo/bin/anon`. Running `cargo install --path .` copies a fresh release build into the cargo bin directory, updating the system-wide binary. During development, use `cargo run --` to guarantee you're testing the local build rather than a stale installed copy. This is a common gotcha when adding new CLI flags — the flag exists in source but the installed binary doesn't know about it yet.
