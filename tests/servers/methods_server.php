<?php
// Exercises every method the CODEBASE_REVIEW.md flagged as documented but
// missing from the method table (clientCount, roomCount, getClients,
// setMaxPayload, onAuth, setThreads) - used by methods_smoke_test.php.
// Calling them here at all (both before listen() and again from inside a
// live request handler) is itself a regression guard: before the fix pass
// referenced in CODEBASE_REVIEW.md, calling any of these was a fatal error
// that would have crashed this script before it ever reached listen().
$port = (int)($argv[1] ?? 0);
if ($port <= 0) {
    fwrite(STDERR, "usage: methods_server.php <port>\n");
    exit(1);
}

$server = new Kislay\EventBus\Server();

// Called before listen() - if any of these fatal, the script dies here and
// the test harness's kislay_test_start_server() will fail with "did not
// start listening", which itself is a clear failure signal.
$server->setThreads(2);
$server->setMaxPayload(500000);
$server->onAuth(function ($socket) {
    return true;
});

$server->on('connection', function ($client) {
    fwrite(STDOUT, sprintf("connected %s\n", $client->id()));
});

$server->on('subscribe', function ($client, $data) {
    $room = trim((string)($data['room'] ?? ''));
    if ($room === '') {
        return;
    }
    $client->join($room);
});

$server->on('probe', function ($client) use ($server) {
    $client->reply('probe-result', [
        'clientCount' => $server->clientCount(),
        'roomCount' => $server->roomCount(),
        'clients' => $server->getClients(),
    ]);
});

// Also called again at runtime, from inside a live request handler, to
// prove they work post-listen() too, not just at script startup.
$server->on('probe2', function ($client) use ($server) {
    $client->reply('probe2-result', [
        'setThreads' => $server->setThreads(4),
        'setMaxPayload' => $server->setMaxPayload(750000),
        'onAuth' => $server->onAuth(function ($socket) {
            return true;
        }),
    ]);
});

$server->on('disconnect', function ($client) {
    fwrite(STDOUT, sprintf("disconnected %s\n", $client->id()));
});

fwrite(STDOUT, sprintf("listening on 127.0.0.1:%d\n", $port));
$server->listen('127.0.0.1', $port, '/socket.io/');
