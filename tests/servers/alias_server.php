<?php
// Used by alias_semantics_test.php to document the current (as-flagged-by
// CODEBASE_REVIEW.md) behavior that Server::emit()/publish()/send() are all
// identical broadcast-to-everyone aliases - so a future accidental
// divergence between them is caught by a failing test instead of silently
// shipping.
$port = (int)($argv[1] ?? 0);
if ($port <= 0) {
    fwrite(STDERR, "usage: alias_server.php <port>\n");
    exit(1);
}

$server = new Kislay\EventBus\Server();

$server->on('connection', function ($client) {
    fwrite(STDOUT, sprintf("connected %s\n", $client->id()));
});

$server->on('trigger-emit', function ($client) use ($server) {
    $server->emit('via-emit', ['from' => 'emit']);
});

$server->on('trigger-publish', function ($client) use ($server) {
    $server->publish('via-publish', ['from' => 'publish']);
});

$server->on('trigger-send', function ($client) use ($server) {
    $server->send('via-send', ['from' => 'send']);
});

fwrite(STDOUT, sprintf("listening on 127.0.0.1:%d\n", $port));
$server->listen('127.0.0.1', $port, '/socket.io/');
