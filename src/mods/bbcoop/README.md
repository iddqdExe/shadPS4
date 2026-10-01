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
| `binding/` | M2 game_binding | Pure binding primitives: signatures, resolver, patch table, relocator, detours, hook planning and the hook handler guard; generated EU 1.09 data in `binding/data/` (written by `tools/re/Generate-Signatures.ps1` of the parent repository, never edited by hand) behind `binding/symbols.h`. |
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

## Game thread

`runtime/game_thread.h` is the one place where mod code touches the game safely: everything that
reads the game's data or calls its functions (`CallGame`, the game API) runs on the game thread,
from a per-frame tick.

| Call | Use |
|---|---|
| `OnEveryFrame(owner, callback)` | Per-frame callback, called with the tick number (from 1) in registration order. Register before the game is loaded (from `BBCoop::Initialize()`). |
| `PostToGameThread(task)` | Queue work for the next tick from any thread; `false` (check it) when the mod is inactive or 256 tasks are already waiting. Dropped tasks are counted and the total is added to the periodic tick line. |
| `IsGameThread()` / `FrameCount()` | Thread check and tick counter. `IsGameThread()` is false everywhere until the first tick. |
| `CallGame<R>(symbol, args...)` | Call a game function by symbol (game thread, after the first tick; System V ABI). Arguments must be integers, enums, pointers or floats; pass `std::uint64_t` / `std::int64_t` explicitly for 64-bit parameters, no bare literals. |

**Tick point.** The tick is a hook on `idle_heartbeat_epilogue`, RVA `0x01BFE882`: the
`add rsp,0x7E8` (7 bytes `48 81 C4 E8 07 00 00`) before the register pops and the `ret` of the
function at `0x01BFB2A0` (the per-frame idle/heartbeat function; in the world it ticks about 60
times per second, see "Game states"). It is installed as a `Mid` hook and steals
exactly that instruction. Checked on the decrypted EU 1.09 ELF: no direct branch or call
anywhere in the image, and no RIP-relative operand, targets the bytes inside the stolen region
(`0x01BFE883..0x01BFE888`), and the function has no indirect jump (so no jump table). The first
thread that reaches the tick becomes the game thread; ticks from any other thread are ignored
with one error line. If the hook were ever refused, the only per-frame fallback is
`sos_status_update` (`0x01872360`, hooked as `FunctionEntry`); it is not a required symbol today, so
switching means making its row required in `docs/re/eu109-symbols.extra.tsv` and regenerating the
tables (`Build-SymbolDb`, `Generate-Signatures`, `bbcoop_sigcheck`).

**Stack budget.** Callbacks and tasks run on the game's stack inside the hook handler: 16 KB at
most for the callback and everything it calls (a `CallGame` target's own stack use counts too), no
deep recursion, no large stack buffers (the game's stacks have no guard page).

**Blocking.** They also run inside the game's frame: anything that blocks (I/O, waiting for another
thread, a contended lock) stalls the game. Do such work on another thread and post the result back
with `PostToGameThread`.

**Nested ticks.** If a task or callback calls into the game and that code reaches the per-frame site
again on the same thread, the nested tick is skipped (error line `nested per-frame tick skipped`,
logged for the first one and then every 1800th).

**Exceptions.** An exception that leaves a task or a callback is caught and logged
(`game-thread task threw`, `frame callback '<owner>' threw`, or the `unknown exception` variants).
A task is dropped; a callback is disabled for good. The tick keeps running.
`[debug] self_test_exceptions = true` in `bbcoop.toml` proves this in the game: two callbacks
(`self_test_std_exception` and `self_test_unknown_exception`) each throw once on the first tick.
Expected: the two `threw` lines, ticks go on, no `Unhandled Exception` line.

**Log.** `BB Co-op active: 1 hooks, 0 patches`, `game thread tick started`, then
`tick: frame N (R ticks/s)` every 1800 ticks (`, D posted tasks dropped so far` is appended when
`PostToGameThread` has refused tasks). Filter a log with `grep -E "\[BBCoop|BB Co-op"` (plain words
such as `tick` or `disabled` also match emulator lines).

**Game states.** Observed in bench run `20261002-000218-b8-tick` (profile p1 with user patches,
`self_test_exceptions = true`, one pass through title screen, save load, Options menu and a lantern
trip to Central Yharnam):
- Title screen: no tick. `game thread tick started` (thread `Game:Main`) came 23 s after the mod
  activated, right as the save began loading; the Hunter's Dream map (m21) opened 1.4 s later.
  Until then `FrameCount()` is 0 and `IsGameThread()` is false.
- World: about 60 ticks per second (`tick: frame 3600` 59.5, `tick: frame 10800` 59.8). The window
  ending at frame 9000 measured 56.0 and was not examined further.
- Pause: the tick keeps running with the Options menu open (a window that contained about 20 s of
  the menu measured 60.0 ticks/s); Bloodborne does not pause the game.
- Loading screens between areas: ticks slow down or stop for a few seconds (the window with the
  lantern travel to Central Yharnam, m24, measured 54.0 ticks/s). The first window (51.3 ticks/s)
  contains the save load.
- Caveat: the rate lines average 1800 ticks (about 30 s at 60 per second), so a loading screen
  shows only as a dip of the average. How long ticks stop, and whether they stop completely or
  just slow down, was not measured; code that must know has to count ticks itself (`FrameCount()`).
- No `second thread` line and no `Unhandled Exception` line; the two `self_test_*` callbacks threw
  once each and were disabled, and the game behaved normally.
