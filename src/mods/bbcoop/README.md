<!--
SPDX-FileCopyrightText: 2026 BB Co-op contributors
SPDX-License-Identifier: GPL-2.0-or-later
-->

# BB Co-op mod

Bloodborne (CUSA03173 EU 1.09) seamless co-op, built into this shadPS4 fork.
Design spec: `docs/superpowers/specs/2026-09-30-bloodborne-seamless-coop-design.md` in the
parent repository.

| Folder | Module (spec §9) | Contents |
|---|---|---|
| `core/` | shared | Pure logic without emulator dependencies (config, queues, policies). Built into `bbcoop_core`. |
| `binding/` | M2 game_binding | Pure binding primitives: signatures, resolver, patch table, relocator, detours; generated EU 1.09 data in `binding/data/` (written by `tools/re/Generate-Signatures.ps1` of the parent repository, never edited by hand) behind `binding/symbols.h`. |
| `runtime/` | M2 game_binding | Glue that touches emulator internals: mod entry points, guest memory, hooks, game thread, game API. Compiled into `shadps4`. |
| `session/` | M6 coop/session | Stage 2 |
| `travel/` | M7 coop/travel | Stage 3 |
| `death/` | M8 coop/death | Stage 3 |
| `sync/` | M9 coop/sync | Stage 4 |
| `ui/` | M10 ui/overlay | Stages 1–4 |
| `community/` | M5 community_service | Stage 1 |
| `tests/` | — | GoogleTest unit tests for `bbcoop_core` (`-DBBCOOP_TESTS=ON`, test names `BBCoop.*`) |
| `tools/` | M2 game_binding | `bbcoop_sigcheck <eboot.elf>`: offline check of the generated EU 1.09 tables against a decrypted eboot (fingerprint, reference and scan resolution, patch bytes). Needs the ELF, so it does not run in CI; `tests/symbols_test.cpp` checks the tables' consistency there. |

Rule: files outside `runtime/` must not include emulator headers. `bbcoop_core` only has
`src/mods` on its include path, so such includes fail to compile.
