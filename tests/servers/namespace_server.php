<?php
// Used by namespace_test.php to exercise Server::namespace() /
// Kislay\EventBus\EventNamespace. See docs.md for the documented scope of
// this feature (a useful subset of full Socket.IO namespaces).
$port = (int)($argv[1] ?? 0);
if ($port <= 0) {
    fwrite(STDERR, "usage: namespace_server.php <port>\n");
    exit(1);
}

$server = new Kislay\EventBus\Server();

// Default namespace ("/") - must keep working exactly as before namespace()
// existed.
$server->on('connection', function ($client) {
    fwrite(STDOUT, sprintf("default-ns connected %s\n", $client->id()));
});
$server->on('ping', function ($client) {
    $client->reply('pong', ['ns' => 'default']);
});

$admin = $server->namespace('/admin');
fwrite(STDOUT, sprintf("admin namespace name() = %s\n", $admin->name()));

$admin->on('connection', function ($client) {
    fwrite(STDOUT, sprintf("admin-ns connected %s\n", $client->id()));
});
$admin->on('ping', function ($client) use ($admin) {
    $admin->emit('pong', ['ns' => $admin->name()]);
});

fwrite(STDOUT, sprintf("listening on 127.0.0.1:%d\n", $port));
$server->listen('127.0.0.1', $port, '/socket.io/');
