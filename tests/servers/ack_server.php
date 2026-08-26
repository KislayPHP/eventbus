<?php
// Used by ack_test.php to exercise the new onWithAck() implementation.
$port = (int)($argv[1] ?? 0);
if ($port <= 0) {
    fwrite(STDERR, "usage: ack_server.php <port>\n");
    exit(1);
}

$server = new Kislay\EventBus\Server();

$server->on('connection', function ($client) {
    fwrite(STDOUT, sprintf("connected %s\n", $client->id()));
});

// Ack-enabled: the handler's return value is sent back as an ACK packet to
// the client that sent the ack id.
$server->onWithAck('sum', function ($client, $data) {
    $a = (int)($data['a'] ?? 0);
    $b = (int)($data['b'] ?? 0);
    return $a + $b;
});

// Plain on() for an event the client may ALSO attach an ack id to - proves
// ack replies are opt-in per event (only onWithAck()-registered events ack),
// not driven purely by whether the incoming packet happened to carry an id.
$server->on('echo-no-ack', function ($client, $data) {
    return $data;
});

$server->on('disconnect', function ($client) {
    fwrite(STDOUT, sprintf("disconnected %s\n", $client->id()));
});

fwrite(STDOUT, sprintf("listening on 127.0.0.1:%d\n", $port));
$server->listen('127.0.0.1', $port, '/socket.io/');
