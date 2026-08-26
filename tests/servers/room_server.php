<?php
// Room join/leave/broadcast server used by rooms_test.php. Adapted from the
// sibling kislayphp/socket module's tests/servers/room_server.php - same
// API shape (Server::on/emitTo, Socket::join/leave).
$port = (int)($argv[1] ?? 0);
if ($port <= 0) {
    fwrite(STDERR, "usage: room_server.php <port>\n");
    exit(1);
}

$server = new Kislay\EventBus\Server();

$server->on('connection', function ($client) {
    fwrite(STDOUT, sprintf("connected %s\n", $client->id()));
});

$server->on('subscribe', function ($client, $data) {
    $room = trim((string)($data['room'] ?? ''));
    if ($room === '') {
        return;
    }
    $client->join(sprintf('room:%s', $room));
    fwrite(STDOUT, sprintf("%s joined room:%s\n", $client->id(), $room));
});

$server->on('leave', function ($client, $data) {
    $room = trim((string)($data['room'] ?? ''));
    if ($room === '') {
        return;
    }
    $client->leave(sprintf('room:%s', $room));
    fwrite(STDOUT, sprintf("%s left room:%s\n", $client->id(), $room));
});

$server->on('announce', function ($client, $data) use ($server) {
    $room = trim((string)($data['room'] ?? ''));
    $msg = (string)($data['msg'] ?? '');
    if ($room === '') {
        return;
    }
    $server->emitTo(sprintf('room:%s', $room), 'announced', ['msg' => $msg]);
});

$server->on('disconnect', function ($client) {
    fwrite(STDOUT, sprintf("disconnected %s\n", $client->id()));
});

fwrite(STDOUT, sprintf("listening on 127.0.0.1:%d\n", $port));
$server->listen('127.0.0.1', $port, '/socket.io/');
