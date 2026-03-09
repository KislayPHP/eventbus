# KislayEventBus

> Realtime event transport for KislayPHP — WebSocket-based pub/sub server with rooms, namespaces, acknowledgements, and auth hooks.

[![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## Installation

**Via PIE (recommended):**
```bash
pie install kislayphp/eventbus
```

Add to `php.ini`:
```ini
extension=kislayphp_eventbus.so
```

**Build from source:**
```bash
git clone https://github.com/KislayPHP/eventbus.git
cd eventbus && phpize && ./configure --enable-kislayphp_eventbus && make && sudo make install
```

## Requirements

- PHP 8.2+
- kislayphp/core for co-located HTTP + WebSocket (optional)

## Quick Start

```php
<?php
$server = new Kislay\EventBus\Server();

$server->on('connection', function (Kislay\EventBus\Socket $socket) use ($server) {
    $socket->join('lobby');
    $socket->reply('connected', ['id' => $socket->id()]);

    $server->on('message', function (Kislay\EventBus\Socket $sender, mixed $data) use ($server) {
        $server->emitTo('lobby', 'message', $data);
    });

    $server->on('disconnect', function (Kislay\EventBus\Socket $socket) {
        $socket->leave('lobby');
    });
});

$server->listen('0.0.0.0', 3000, '/events/');
```

## API Reference

### `Server`

#### `__construct()`
Creates a new EventBus server instance.

#### `listen(string $host, int $port, string $path = '/'): bool`
Starts the WebSocket server and blocks until stopped.
- `$host` — bind address, e.g. `'0.0.0.0'`
- `$port` — TCP port
- `$path` — WebSocket upgrade path, e.g. `'/events/'`

#### `on(string $event, callable $handler): bool`
Registers an event handler on the server.
- `$event` — event name; built-in: `'connection'`, `'disconnect'`
- `$handler` — for `'connection'`: `function(Socket $socket): void`; for custom events: `function(Socket $socket, mixed $data): void`

```php
$server->on('connection', function (Kislay\EventBus\Socket $socket) {
    echo "Client connected: " . $socket->id() . "\n";
});
```

#### `listen(string $event, callable $handler): bool`
Alias for `on()`.

#### `emit(string $event, mixed $data): bool`
Broadcasts an event to **all** connected clients.

#### `emitTo(string $room, string $event, mixed $data): bool`
Broadcasts an event to all clients in the named room.
- `$room` — room name, e.g. `'general'`
- Returns `false` if the room does not exist

```php
$server->emitTo('general', 'chat', ['user' => 'Alice', 'text' => 'Hello!']);
```

#### `namespace(string $ns): Server`
Returns a sub-server scoped to the given namespace. Clients must connect to `ws://host:port/path?ns=name`.

#### `onAuth(callable $handler): bool`
Registers an authentication hook called on every new connection before `'connection'` fires.
- Signature: `function(array $headers, string $query): bool`
- Return `true` to allow; `false` to reject the connection with `401`

```php
$server->onAuth(function (array $headers, string $query): bool {
    return ($headers['Authorization'] ?? '') === 'Bearer my-secret';
});
```

#### `clientCount(): int`
Returns the number of currently connected clients.

#### `roomCount(string $room): int`
Returns the number of clients in the named room.

#### `getClients(?string $room = null): array`
Returns an array of socket IDs. Pass a room name to filter to that room.

#### `setMaxPayload(int $bytes): bool`
Sets the maximum allowed WebSocket frame payload size in bytes. Default: `65536`.

---

### `Socket`

Represents a single connected client, passed to event handlers.

#### `id(): string`
Returns the unique socket ID assigned at connection time.

#### `join(string $room): bool`
Adds this socket to the named room. Creates the room if it does not exist.

#### `leave(string $room): bool`
Removes this socket from the named room.

#### `emit(string $event, mixed $data): bool`
Sends an event directly to this socket only.

#### `reply(string $event, mixed $data): bool`
Alias for `emit()`. Semantically indicates a response to the client's last message.

#### `emitTo(string $room, string $event, mixed $data): bool`
Broadcasts from this socket to all clients in a room (including itself).

#### `onWithAck(string $event, callable $handler): bool`
Registers a handler that sends an acknowledgement back to the caller.
- Signature: `function(mixed $data): mixed`
- The return value is sent back as the acknowledgement payload

```php
$socket->onWithAck('ping', function (mixed $data): mixed {
    return ['pong' => true, 'ts' => time()];
});
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KISLAY_EVENTBUS_MAX_PAYLOAD` | `65536` | Max WebSocket frame payload bytes |
| `KISLAY_EVENTBUS_THREADS` | `1` | IO worker threads (clamped to 1 on NTS PHP) |
| `KISLAY_EVENTBUS_AUTH_REQUIRED` | `0` | `1` to enforce `onAuth` on every connection |

## Events

Built-in server events:

| Event | Handler Signature | Description |
|-------|------------------|-------------|
| `connection` | `function(Socket $socket): void` | New client connected |
| `disconnect` | `function(Socket $socket): void` | Client disconnected |

All other event names are user-defined and emitted by clients or server code.

## Examples

### Chat Room

```php
<?php
$server = new Kislay\EventBus\Server();

$server->on('connection', function (Kislay\EventBus\Socket $socket) use ($server) {
    $socket->join('chat');
    $server->emitTo('chat', 'system', ['text' => 'User joined: ' . $socket->id()]);

    $server->on('chat.message', function (Kislay\EventBus\Socket $s, mixed $data) use ($server) {
        $server->emitTo('chat', 'chat.message', [
            'from' => $s->id(),
            'text' => $data['text'] ?? '',
        ]);
    });

    $server->on('disconnect', function (Kislay\EventBus\Socket $s) use ($server) {
        $server->emitTo('chat', 'system', ['text' => 'User left: ' . $s->id()]);
    });
});

$server->listen('0.0.0.0', 3000, '/chat/');
```

### Auth-Gated Connection

```php
$server->onAuth(function (array $headers, string $query): bool {
    parse_str($query, $params);
    return isset($params['token']) && validate_token($params['token']);
});
```

### Namespaces

```php
$admin  = $server->namespace('admin');
$public = $server->namespace('public');

$admin->on('connection', function (Kislay\EventBus\Socket $socket) {
    $socket->reply('welcome', ['role' => 'admin']);
});

$public->on('connection', function (Kislay\EventBus\Socket $socket) {
    $socket->join('general');
});

$server->listen('0.0.0.0', 3000, '/ws/');
```

### Acknowledgement (RPC over WebSocket)

```php
$server->on('connection', function (Kislay\EventBus\Socket $socket) {
    $socket->onWithAck('get_user', function (mixed $data): mixed {
        $user = fetch_user($data['id']);
        return $user ?? ['error' => 'not found'];
    });
});
```

### Stats Endpoint

```php
$app->get('/ws/stats', function ($req, $res) use ($server) {
    $res->json([
        'clients' => $server->clientCount(),
        'lobby'   => $server->roomCount('lobby'),
    ]);
});
```

## Related Extensions

| Extension | Use Case |
|-----------|----------|
| [kislayphp/core](https://github.com/KislayPHP/core) | Run HTTP API alongside the EventBus server |
| [kislayphp/discovery](https://github.com/KislayPHP/discovery) | Broadcast service lifecycle events via `setBus()` |
| [kislayphp/queue](https://github.com/KislayPHP/queue) | Use Queue for durable jobs; EventBus for realtime push |

## License

Licensed under the [Apache License 2.0](LICENSE).
