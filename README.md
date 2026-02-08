# kislayphp_eventbus

A PHP extension that provides a Socket.IO-inspired WebSocket server.

## Build

```sh
phpize
./configure --enable-kislayphp_eventbus
make
```

## Run Locally

```sh
cd /path/to/phpExtension/kislay_socket
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
