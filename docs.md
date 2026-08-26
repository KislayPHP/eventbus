# KislayPHP EventBus Documentation

Kislay EventBus is the compatibility transport package for the older realtime transport name. New transport-facing work should use `kislayphp/socket:0.0.1`.

## What It Is

- Package: `kislayphp/eventbus`
- Published version: `0.0.3`
- Primary namespace: `Kislay\EventBus`
- Compatibility aliases: `KislayPHP\EventBus\...`
- Recommended forward package: `kislayphp/socket:0.0.1`

## When To Use It

Use EventBus when:

- you are maintaining older code already pinned to `kislayphp/eventbus`
- you need namespace compatibility before migrating to `Kislay\Socket\...`
- you want a low-risk transport migration step during `0.0.x`

Do not start new transport projects on EventBus.

## Install

Compatibility install:

```bash
pie install kislayphp/eventbus:0.0.3
```

Forward install for new work:

```bash
pie install kislayphp/socket:0.0.1
```

Enable the compatibility package:

```ini
extension=kislayphp_eventbus.so
```

## API Surface

### `Kislay\EventBus\Server`

```php
on(string $event, callable $handler): bool
emit(string $event, mixed $data): bool
publish(string $event, mixed $data): bool
send(string $event, mixed $data): bool
emitTo(string $room, string $event, mixed $data): bool
listen(string $host, int $port, string $path): bool
clientCount(): int
roomCount(string $room): int
onAuth(callable $handler): bool
onWithAck(string $event, callable $handler): bool
getClients(): array
setMaxPayload(int $bytes): bool
namespace(string $name): Kislay\EventBus\EventNamespace
```

### `Kislay\EventBus\Socket`

```php
id(): string
join(string $room): bool
leave(string $room): bool
emit(string $event, mixed $data): bool
publish(string $event, mixed $data): bool
send(string $event, mixed $data): bool
reply(string $event, mixed $data): bool
emitTo(string $room, string $event, mixed $data): bool
```

Semantics:

- `Server::emit()` broadcasts to all clients.
- `Socket::emit()` sends only to the current client.
- `reply()` is the per-client alias.

### `onWithAck(string $event, callable $handler): bool`

Like `on()`, but registers the handler as ack-enabled. When a client sends
an EVENT packet that carries a Socket.IO ack id (wire format
`42<id>["event",data]` instead of plain `42["event",data]`) for an event
registered via `onWithAck()`, the handler's return value is JSON-encoded
and sent back to that specific client as an ACK packet
(`43<id>[return_value]`) once the handler returns. If the same event is
later re-registered via plain `on()`, ack replies for it turn back off.

Scope/limits:

- Default namespace only - an ack id on a namespace-scoped event packet
  (see `namespace()` below) is not acknowledged in this version.
- Not supported together with binary-attachment events (packets using the
  Socket.IO `BINARY_EVENT` type, i.e. payloads containing binary
  placeholders) - the ack id is not carried through the binary reassembly
  path, so such an event will not receive an ACK reply even if registered
  via `onWithAck()`.
- If the incoming packet carries an ack id for an event that was
  registered via plain `on()` (not `onWithAck()`), no ACK packet is sent -
  acking is opt-in per event, not driven by whether the client happened to
  attach an id.

### `namespace(string $name): Kislay\EventBus\EventNamespace`

Returns a namespace-scoped view of the server: its own `on()`/`emit()`/
`emitTo()`, filtering and wire-tagging by the Socket.IO namespace prefix
(`/name,` before the JSON payload - e.g. `42/admin,["event",data]` instead
of `42["event",data]`) on the shared underlying connection. `$name` is
normalized to always start with `/` (e.g. `'admin'` and `'/admin'` both
produce the `/admin` namespace).

Note on the class name: the docs previously (inaccurately) described this
as returning a `Kislay\EventBus\Namespace` instance - `namespace` is a
reserved word in PHP and cannot be used as a class name (`class Namespace
{}` is a parse error), so the real class is `Kislay\EventBus\EventNamespace`.

**This is a documented, intentional SUBSET of full Socket.IO namespaces,
not a complete implementation.** What's covered:

- `EventNamespace::name(): string` - the namespace name, e.g. `/admin`.
- `EventNamespace::on(string $event, callable $handler): bool` - registers
  a handler that fires only for packets carrying this namespace's prefix.
  A namespaced `CONNECT` packet (`40/admin,`) fires this namespace's
  `on('connection')`, not the default namespace's; a namespaced
  `DISCONNECT` packet (`1/admin,`) fires this namespace's
  `on('disconnect')` without tearing down the underlying connection (see
  below).
- `EventNamespace::emit(string $event, mixed $data): bool` - broadcasts a
  namespace-prefixed packet to every connected socket.
- `EventNamespace::emitTo(string $room, string $event, mixed $data): bool`
  - same, but to members of `$room`.
- The default namespace (`"/"`, i.e. no `namespace()` call at all) behaves
  exactly as it did before this feature existed - bare `on()`/`emit()`/
  packets with no `/name,` prefix are completely unaffected.

What's explicitly NOT covered (rather than silently ignored):

- **No per-namespace connection membership.** There is no separate
  socket/session per namespace - all namespaces share the same underlying
  Engine.IO connection and the same `clients` registry. `emit()` broadcasts
  to *every* connected socket (namespace-prefixed on the wire), not only
  ones that sent a namespaced `CONNECT` packet for that namespace.
- **Rooms are shared server-wide across all namespaces**, not scoped per
  namespace. `Socket::join()`/`leave()` have no namespace context (a
  `Socket` object handed to a handler doesn't know which namespace's
  handler invoked it).
- **No namespace-specific auth** - `onAuth()` is a default-namespace-only,
  server-wide gate; there is no per-namespace auth hook.
- **No ack support for namespaced events** - see `onWithAck()` above.

If a fuller implementation (real per-namespace socket membership, scoped
rooms, per-namespace auth) is needed later, treat this as a starting point,
not a finished feature.

## Minimal Example

```php
<?php

$server = new Kislay\EventBus\Server();

$server->on('connection', function (Kislay\EventBus\Socket $socket) {
    $socket->join('general');
    $socket->reply('welcome', ['id' => $socket->id()]);
});

$server->on('chat', function (Kislay\EventBus\Socket $socket, array $payload) {
    $socket->emitTo('general', 'chat', [
        'from' => $socket->id(),
        'message' => $payload['message'] ?? '',
    ]);
});

$server->listen('0.0.0.0', 3000, '/socket.io/');
```

## Operational Notes

- EventBus is still an async/event-driven transport runtime.
- Treat it as the compatibility package, not the forward transport name.
- Move new docs, examples, and onboarding to `socket`.
- Use `queue` for background processing, retries, or DLQ behavior.

## Common Mistakes

### 1. Starting new code on EventBus

That only creates more migration work later.

### 2. Treating `Socket::emit()` as a broadcast

It is not. Use `Server::emit()` for all-clients broadcast or `Socket::emitTo()` for rooms.

### 3. Using EventBus as a durable event platform

This package is a realtime transport runtime. It is not a queue and not a durable event log.

## Migration Direction

- keep existing EventBus installs stable
- move new installs to `socket`
- migrate namespaces gradually from `Kislay\EventBus\...` to `Kislay\Socket\...`
- rely on compatibility aliases during the `0.0.x` line where needed
