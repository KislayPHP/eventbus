# KislayPHP EventBus Documentation

Primary namespace is `Kislay\EventBus` with backward-compatible aliases under `KislayPHP\EventBus`.

## API Surface

### `Kislay\EventBus\Server`

```php
__construct()
on(string $event, callable $handler): bool
emit(string $event, mixed $data): bool
publish(string $event, mixed $data): bool
send(string $event, mixed $data): bool
emitTo(string $room, string $event, mixed $data): bool
listen(string $host, int $port, string $path): bool
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

### Legacy aliases

- `KislayPHP\EventBus\Server`
- `KislayPHP\EventBus\Socket`

## Concurrency Model

- EventBus is runtime event-driven and callback-based.
- It is one of the async/event-driven modules in the ecosystem policy.
- API methods themselves are immediate (no Promise-returning methods in this extension API).

## Example

```php
<?php

$server = new Kislay\EventBus\Server();

$server->on('connection', function (Kislay\EventBus\Socket $socket) use ($server) {
    $socket->join('global');
    $socket->reply('welcome', ['id' => $socket->id()]);

    $server->on('message', function (Kislay\EventBus\Socket $client, $data) use ($server) {
        $server->emitTo('global', 'message', $data);
    });
});

$server->listen('0.0.0.0', 3000, '/events/');
```

## Install

```bash
pie install kislayphp/eventbus
```

```ini
extension=kislayphp_eventbus.so
```

