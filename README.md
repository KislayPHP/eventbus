# KislayPHP EventBus

KislayPHP EventBus is a C++ PHP extension that provides a Socket.IO-style realtime server for PHP applications.

## Key Features

- Socket.IO v4 and Engine.IO compatible transport.
- WebSocket and long-polling support.
- Rooms and broadcast helpers for fan-out messaging.
- Configurable ping and payload limits via INI or env.

## Use Cases

- Realtime dashboards and notifications.
- Low-latency chat or presence features.
- Event fan-out between PHP services.

## SEO Keywords

PHP realtime, Socket.IO server, WebSocket, Engine.IO, C++ PHP extension, event bus

## Repository

- https://github.com/KislayPHP/eventbus

## Related Modules

- https://github.com/KislayPHP/core
- https://github.com/KislayPHP/discovery
- https://github.com/KislayPHP/gateway
- https://github.com/KislayPHP/config
- https://github.com/KislayPHP/metrics
- https://github.com/KislayPHP/queue

## Build

```sh
phpize
./configure --enable-kislayphp_eventbus
make
```

## Run Locally

```sh
cd /path/to/eventbus
php -d extension=modules/kislay_socket.so example.php
```

## Example

```php
<?php
extension_loaded('kislayphp_eventbus') or die('kislayphp_eventbus not loaded');

$io = new KislayPHP\EventBus\Server();

$io->on('connection', function ($socket) use ($io) {
    $socket->join('room-1');
    $socket->emit('welcome', ['id' => $socket->id()]);
});

$io->on('message', function ($socket, $payload) {
    $socket->emitTo('room-1', 'message', $payload);
});

$io->on('binary', function ($socket, $payload) {
    $socket->emit('binary', $payload);
});

$io->listen('0.0.0.0', 8090, '/socket.io/');
// This call blocks; stop with Ctrl+C.
?>
```
