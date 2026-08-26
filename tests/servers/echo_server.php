<?php
// Minimal connect/emit/disconnect server used by connection_basics_test.php.
// Mirrors README.md's own "Minimal Example" (on('connection') -> join +
// reply('welcome', ...)) so the documented example itself is exercised.
$port = (int)($argv[1] ?? 0);
if ($port <= 0) {
    fwrite(STDERR, "usage: echo_server.php <port>\n");
    exit(1);
}

$server = new Kislay\EventBus\Server();

$server->on('connection', function ($client) {
    fwrite(STDOUT, sprintf("connected %s\n", $client->id()));
    $client->join('general');
    $client->reply('welcome', ['id' => $client->id()]);
});

$server->on('chat', function ($client, $data) use ($server) {
    $server->emit('chat', ['from' => $client->id(), 'message' => $data['message'] ?? '']);
});

$server->on('disconnect', function ($client) {
    fwrite(STDOUT, sprintf("disconnected %s\n", $client->id()));
});

fwrite(STDOUT, sprintf("listening on 127.0.0.1:%d\n", $port));
$server->listen('127.0.0.1', $port, '/socket.io/');
