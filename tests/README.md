# kislay_socket/eventbus tests

This module previously had zero real test coverage (`tests/` was a stub and
`run-tests.php` had nothing to run), despite a history of documented-but-
unimplemented methods reaching users as fatal errors. This suite exists to
catch that class of bug going forward.

## Running

Build the extension first:

```sh
phpize
./configure --enable-kislayphp_eventbus
make
```

Then run all tests:

```sh
php tests/run_all.php
```

Or run a single test file directly:

```sh
php tests/connection_basics_test.php
```

Each test spawns the real compiled extension (`modules/kislayphp_eventbus.so`)
as a separate PHP CLI process running one of `tests/servers/*.php`, then
drives it over real HTTP (curl) exactly like a browser/curl client would -
see `tests/_harness.php` for the shared helpers. This pattern is adapted
from the sibling `kislayphp/socket` module's `tests/_harness.php`, which
solved this same "drive a real spawned extension process over the Engine.IO/
Socket.IO polling transport" problem first.

### Why not the standard `run-tests.php`/`.phpt` harness (`make test`)?

`make test` still works and will simply report "no tests to run" - this
suite deliberately does NOT use `.phpt` files. `make test`'s generated
Makefile target invokes `run-tests.php` with `-n` (no php.ini), which does
not load ext-curl or ext-posix unless explicitly requested, and these tests
need to spawn a background child server process (posix_kill to stop it
cleanly) and drive it over HTTP concurrently with it running - a poor fit
for `.phpt`'s synchronous `--FILE--`/`--EXPECT--` model. Driving the
extension as a real out-of-process server is also more representative of
how it's actually used in production.

## Coverage

- `connection_basics_test.php` - `Server` construction, `listen()`, a
  connect -> `on('connection')` fires -> `emit()`/`reply()` -> client
  receives round trip, and disconnect.
- `methods_smoke_test.php` - every method the codebase review flagged as
  documented-but-missing-from-the-method-table and fatal-erroring when
  called: `clientCount()`, `roomCount()`, `getClients()`,
  `setMaxPayload()`, `onAuth()`, `setThreads()`. Calls each at server
  startup AND again from inside a live request handler, and asserts they
  don't fatal and return sane values.
- `alias_semantics_test.php` - documents that `Server::emit()`,
  `publish()`, and `send()` are currently identical broadcast-to-everyone
  aliases, so a future accidental divergence between them fails a test
  instead of shipping silently.
- `ack_test.php` - the new `onWithAck()` implementation: an incoming EVENT
  packet carrying a Socket.IO ack id gets the handler's return value back
  as an ACK packet, and only for events registered via `onWithAck()` (not
  plain `on()`), even if the packet itself carried an ack id.
- `namespace_test.php` - the new `Server::namespace()` /
  `Kislay\EventBus\EventNamespace` implementation: namespace-scoped
  `on()`/`emit()`, namespace-prefixed wire packets, and that the default
  namespace's behavior is completely unaffected by namespaces existing.
  See `docs.md` for the documented scope of this feature (it's a useful
  subset of full Socket.IO namespaces, not a complete implementation).
- `rooms_test.php` - `Socket::join()`/`leave()` + `Server::emitTo()`
  deliver only to room members, and `leave()` stops further delivery
  without affecting other members.

## A real bug this suite caught during development

Writing `namespace_test.php` surfaced a genuine heap corruption bug (not a
namespace-logic bug) in the object layout used by `Server`, `Socket`, and
the new `EventNamespace` classes: `zend_object std` was declared as the
**first** member of each backing C++ struct. `zend_object` ends with its
own embedded `zval properties_table[1]` placeholder, and
`zend_object_properties_size(ce)` is defined by the Zend engine to return
`sizeof(zval) * (default_properties_count - 1)` - an intentional `size_t`
underflow to "minus one zval" for any class with zero declared PHP
properties (all three classes here). `ecalloc(1, sizeof(struct) +
zend_object_properties_size(ce))` only computes the correct allocation size
when that trailing placeholder zval is the very last thing in the
allocation (i.e. `zend_object` is the **last** struct member) - with it
first, the same arithmetic silently under-allocates every object of these
classes by 16 bytes (one zval), corrupting whatever the last 16 bytes of
the intended struct happened to be. This had apparently been silently
"working" for `Server`/`Socket` (the overflow likely landing in allocator
bin slack most of the time) until the new `EventNamespace` class's
different allocation pattern/timing exposed it as a real, reproducible
`zend_mm_heap corrupted` crash. Fixed by moving `zend_object std` to be the
last member of all three structs (`kislay_socket.cpp`); see the comment
above `php_kislay_socket_server_t` for the full explanation.
