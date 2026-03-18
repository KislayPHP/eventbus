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
namespace(string $ns): Kislay\EventBus\Namespace
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
