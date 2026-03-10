# KislayPHP EventBus

[![PHP Version](https://img.shields.io/badge/PHP-8.2%2B-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/KislayPHP/eventbus/ci.yml?branch=main&label=CI)](https://github.com/KislayPHP/eventbus/actions)
[![PIE](https://img.shields.io/badge/install-pie-blueviolet)](https://github.com/php/pie)

> **Realtime event transport for PHP.** WebSocket-style rooms, fanout, and push — all as a native PHP extension. No Node.js, no socket.io server, no separate process.

Part of the [KislayPHP ecosystem](https://skelves.com/kislayphp/docs).

---

## ✨ What It Does

`kislayphp/eventbus` is a PHP C++ extension providing a realtime event server. Clients connect over WebSocket-compatible sockets, join named rooms, and receive server-pushed events. The API mirrors socket.io semantics in pure PHP.

```php
<?php
$server = new Kislay\EventBus\Server();

$server->on('connection', function(Kislay\EventBus\Socket $socket) use ($server) {
    $socket->join('general');
    $server->on('chat', fn($client, $msg) => $server->emitTo('general', 'chat', $msg));
});

$server->listen('0.0.0.0', 3000, '/events/');
```

---

## 📦 Installation

```bash
pie install kislayphp/eventbus
```

Enable in `php.ini`:
```ini
extension=kislayphp_eventbus.so
```

---

## 🚀 Quick Start

### Chat Room Server

```php
<?php
$server = new Kislay\EventBus\Server();

$server->on('connection', function(Kislay\EventBus\Socket $socket) use ($server) {
    echo "[connect] " . $socket->id() . "\n";

    // Auto-join the general room
    $socket->join('general');

    // Acknowledge connection
    $socket->reply('connected', [
        'id'    => $socket->id(),
        'room'  => 'general',
        'users' => count_online(),
    ]);

    // Broadcast chat messages to the room
    $server->on('chat', function(Kislay\EventBus\Socket $client, $payload) use ($server) {
        $server->emitTo('general', 'chat', [
            'from'    => $client->id(),
            'message' => $payload['text'],
            'ts'      => time(),
        ]);
    });

    // Handle room switching
    $server->on('join-room', function(Kislay\EventBus\Socket $client, $payload) {
        $client->leave('general');
        $client->join($payload['room']);
        $client->reply('room-joined', ['room' => $payload['room']]);
    });
});

$server->listen('0.0.0.0', 3000, '/events/');
```

### Notification Push Server

```php
<?php
$server = new Kislay\EventBus\Server();

$server->on('connection', function(Kislay\EventBus\Socket $socket) {
    // Client provides their user ID
    $socket->on('auth', function($data) use ($socket) {
        $socket->join("user-{$data['user_id']}");
    });
});

// Push notification to specific user (from anywhere in your app)
function notify(Kislay\EventBus\Server $server, int $userId, array $data): void {
    $server->emitTo("user-{$userId}", 'notification', $data);
}
```

---

## 📖 Public API

```php
namespace Kislay\EventBus;

class Server {
    public function __construct();
    public function on(string $event, callable $handler): bool;
    public function emit(string $event, mixed $data): bool;          // broadcast to all
    public function publish(string $event, mixed $data): bool;       // alias for emit
    public function send(string $event, mixed $data): bool;          // alias for emit
    public function emitTo(string $room, string $event, mixed $data): bool;
    public function listen(string $host, int $port, string $path): bool;
}

class Socket {
    public function id(): string;
    public function join(string $room): bool;
    public function leave(string $room): bool;
    public function emit(string $event, mixed $data): bool;          // to all
    public function reply(string $event, mixed $data): bool;         // to this socket only
    public function emitTo(string $room, string $event, mixed $data): bool;
}
```

Legacy aliases: `KislayPHP\EventBus\Server`, `KislayPHP\EventBus\Socket`

---

## 💡 When to Use Each Extension

| Need | Use |
|---|---|
| Realtime push to connected browser clients | **eventbus** (this) |
| Async background task processing | [core](https://github.com/KislayPHP/core) `async()` |
| Reliable job queue with retry | [queue](https://github.com/KislayPHP/queue) |

---

## 🔗 Ecosystem

[core](https://github.com/KislayPHP/core) · [gateway](https://github.com/KislayPHP/gateway) · [discovery](https://github.com/KislayPHP/discovery) · [metrics](https://github.com/KislayPHP/metrics) · [queue](https://github.com/KislayPHP/queue) · **eventbus**

## 📄 License

[Apache License 2.0](LICENSE) · **[Full Docs](https://skelves.com/kislayphp/docs)**
