# kislayphp/eventbus — notes for AI assistants

**Compatibility package.** `Kislay\EventBus\*` is the older realtime
transport name — this repo stays on the `0.0.x` line specifically so
services already pinned to it keep working. **New transport work belongs
in `kislayphp/socket`** (its "active successor," per socket's own source
comments), not here. Only touch this repo for: an existing service pinned
to `eventbus:0.0.3`, or code still importing `Kislay\EventBus\Server`/
`Kislay\EventBus\Socket` that needs a low-risk fix without a full
migration to `socket`.

Architecturally near-identical to `socket` (same civetweb-based
socket.io-style server, in `kislay_socket.cpp`) — if you're fixing
something here, **check whether `socket`'s `CLAUDE.md` documents the same
bug class already fixed there**, and vice versa if you're working in
`socket`. The two codebases have diverged enough that a fix in one is not
automatically present in the other (see the num_threads example below).

## Already ahead of `socket` on one specific bug class

`eventbus` already has `setThreads()` + `KISLAYPHP_EVENTBUS_THREADS` (env
var, default 4 threads) for civetweb's `num_threads` option — `socket` did
**not** have this until 2026-08-30, when a hardcoded `num_threads=1` was
found to cause real thread-starvation (one abandoned long-poll connection
could starve every other concurrent connection on the same server for up
to `ping_interval_ms`). Audited 2026-08-30 specifically to confirm
`eventbus` doesn't have the identical bug — it doesn't, this mechanism was
already in place. If you're porting a fix from `socket` back into
`eventbus` (or vice versa), don't assume symmetry; verify each fix
actually applies to both codebases' current state rather than
copy-pasting blind.

## Other things already fixed, worth knowing

- A struct-layout bug (`zend_object std` not being the last member of a
  custom object struct) caused a real heap-corruption crash here — fixed.
  Every custom object struct in this file must keep `std` as the **last**
  member; re-check after any struct edit.
- `onWithAck()`/`namespace()` were previously unimplemented (silently
  no-op or missing) — now implemented, covered by a 60-assertion test
  suite added from scratch.

## Testing

**Not phpt** — uses a custom harness: `php tests/run_all.php` runs 6 test
files (currently: connection basics, ack, alias semantics, methods smoke,
namespace, rooms) against real spawned server subprocesses via
`tests/_harness.php`, driven with real HTTP requests. 12/12 assertions
across those files pass as of 2026-08-30 (audited, no changes needed this
pass).

## Known open issues

None specific to this module as of 2026-08-30.
