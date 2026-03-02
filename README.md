# KislayPHP EventBus

Realtime event transport for KislayPHP.

Primary runtime namespace is `Kislay\EventBus` with backward-compatible aliases under `KislayPHP\EventBus`.

## Concurrency Mode

- EventBus is event-driven at runtime (connection loop + callbacks).
- Server APIs are callback-based and suitable for realtime workloads.
- This is one of the async/event-driven modules in the ecosystem policy.

## Installation

```bash
pie install kislayphp/eventbus
```

Enable in `php.ini`:

```ini
extension=kislayphp_eventbus.so
```

## Public API

`Kislay\EventBus\Server`:

- `__construct()`
- `on(string $event, callable $handler): bool`
- `emit(string $event, mixed $data): bool`
- `publish(string $event, mixed $data): bool` (alias)
- `send(string $event, mixed $data): bool` (alias)
- `emitTo(string $room, string $event, mixed $data): bool`
- `listen(string $host, int $port, string $path): bool`

`Kislay\EventBus\Socket`:

- `id(): string`
- `join(string $room): bool`
- `leave(string $room): bool`
- `emit(string $event, mixed $data): bool`
- `publish(string $event, mixed $data): bool` (alias)
- `send(string $event, mixed $data): bool` (alias)
- `reply(string $event, mixed $data): bool`
- `emitTo(string $room, string $event, mixed $data): bool`

Legacy aliases:

- `KislayPHP\EventBus\Server`
- `KislayPHP\EventBus\Socket`

## Quick Start

```php
<?php

$server = new Kislay\EventBus\Server();

$server->on('connection', function (Kislay\EventBus\Socket $socket) use ($server) {
    $socket->join('general');
    $socket->reply('connected', ['id' => $socket->id()]);

    $server->on('chat', function (Kislay\EventBus\Socket $client, $payload) use ($server) {
        $server->emitTo('general', 'chat', $payload);
    });
});

$server->listen('0.0.0.0', 3000, '/events/');
```

## Notes

- Use EventBus for realtime push/fanout.
- For request/response HTTP and middleware, use `kislayphp/core`.
- For queue semantics, use `kislayphp/queue`.

