# KislayPHP EventBus

> Compatibility transport package for the older Kislay realtime transport name.

`kislayphp/eventbus` remains published on the `0.0.x` line so existing transport installs can continue to work. New transport work should start on [`kislayphp/socket`](https://github.com/KislayPHP/socket).

## Current Role

Use `eventbus` only when:

- an existing service is already pinned to `kislayphp/eventbus:0.0.3`
- existing code already imports `Kislay\EventBus\Server` or `Kislay\EventBus\Socket`
- you want the lowest-risk migration path before moving code to `Kislay\Socket\...`

Use `socket` for new installs when you need:

- realtime browser or service socket connections
- Engine.IO polling and WebSocket upgrade
- rooms and namespaces
- per-client replies and room fanout

## Installation

### Compatibility install

```bash
pie install kislayphp/eventbus:0.0.3
```

Enable it in `php.ini`:

```ini
extension=kislayphp_eventbus.so
```

### Forward install for new transport work

```bash
pie install kislayphp/socket:0.0.1
```

## Minimal Compatibility Example

```php
<?php

$server = new Kislay\EventBus\Server();

$server->on('connection', function (Kislay\EventBus\Socket $socket) {
    $socket->join('general');
    $socket->reply('connected', ['id' => $socket->id()]);
});

$server->on('chat', function (Kislay\EventBus\Socket $socket, array $payload) {
    $socket->emitTo('general', 'chat', [
        'from' => $socket->id(),
        'message' => $payload['message'] ?? '',
    ]);
});

$server->listen('0.0.0.0', 3000, '/socket.io/');
```

## Public API

### `Kislay\EventBus\Server`

- `on(string $event, callable $handler): bool`
- `emit(string $event, mixed $data): bool`
- `publish(string $event, mixed $data): bool`
- `send(string $event, mixed $data): bool`
- `emitTo(string $room, string $event, mixed $data): bool`
- `listen(string $host, int $port, string $path): bool`
- `clientCount(): int`
- `roomCount(string $room): int`
- `onAuth(callable $handler): bool`
- `onWithAck(string $event, callable $handler): bool`
- `getClients(): array`
- `setMaxPayload(int $bytes): bool`
- `namespace(string $name): Kislay\EventBus\EventNamespace`

### `Kislay\EventBus\Socket`

- `id(): string`
- `join(string $room): bool`
- `leave(string $room): bool`
- `emit(string $event, mixed $data): bool`
- `publish(string $event, mixed $data): bool`
- `send(string $event, mixed $data): bool`
- `reply(string $event, mixed $data): bool`
- `emitTo(string $room, string $event, mixed $data): bool`

### `Kislay\EventBus\EventNamespace`

Returned by `Server::namespace()`. A **documented subset** of full
Socket.IO namespaces - see `docs.md` for exactly what is and isn't covered
(notably: no per-namespace connection membership, rooms are shared across
namespaces, no namespace-specific auth or acks).

- `name(): string`
- `on(string $event, callable $handler): bool`
- `emit(string $event, mixed $data): bool`
- `emitTo(string $room, string $event, mixed $data): bool`

Semantics:

- `Server::emit()` broadcasts to all connected clients.
- `Socket::emit()` sends only to the current client.
- `Socket::reply()` is the semantic alias for per-client emit.
- `Socket::emitTo()` broadcasts to a room.
- `onWithAck()` is like `on()`, but the handler's return value is sent back
  to the sending client as a Socket.IO ACK packet when the incoming packet
  carried an ack id - see `docs.md` for the exact wire format and scope
  (default namespace only, no binary-attachment events).

Legacy aliases under `KislayPHP\EventBus\...` remain available.

## Positioning

Use `eventbus` only as the compatibility package during the `0.0.x` transport split.

Use `queue` for:

- background jobs
- retries and DLQ
- worker/server queue processing

Use `socket` for:

- new realtime transport work
- rooms and namespaces
- polling and WebSocket upgrade
- transport-facing docs and onboarding

## Documentation

- Socket docs: [https://skelves.com/kislayphp/docs/socket](https://skelves.com/kislayphp/docs/socket)
- EventBus compatibility docs: [https://skelves.com/kislayphp/docs/eventbus](https://skelves.com/kislayphp/docs/eventbus)
- Ecosystem docs: [https://skelves.com/kislayphp/docs](https://skelves.com/kislayphp/docs)
