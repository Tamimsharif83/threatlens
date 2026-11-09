# EVTX test fixtures

Small Windows event logs for the EVTX tests. They come from the sample files of
the `evtx` Rust library (https://github.com/omerbenamram/evtx, `samples/`),
which is dual-licensed MIT / Apache-2.0; see `LICENSE-MIT` in this folder.

| File | Source sample | Change |
|---|---|---|
| `security-new-user.evtx` | `new-user-security.evtx` | none (4720 user created, 4728/4732 group adds) |
| `security-short.evtx` | `Security_short_selected.evtx` | none (4625, 4776, 5152, ...) |
| `sysmon.evtx` | `sysmon.evtx` | first chunk only, header updated (41 records: EventID 1, 10, 11, 13) |
| `system.evtx` | `system.evtx` | first chunk only, header updated (108 records, incl. 7045) |

"First chunk only" keeps the 4 KiB file header and the first 64 KiB chunk, and
rewrites the header's chunk count, last chunk number, next record id and CRC32.
