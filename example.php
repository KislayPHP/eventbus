<?php

// Run from this folder with:
// php -d extension=modules/kislay_socket.so example.php

extension_loaded('kislayphp_eventbus') or die('kislayphp_eventbus not loaded');

$io = new KislayPHP\EventBus\Server();

$io->on('connection', function ($socket) {
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
