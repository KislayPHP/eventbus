<?php
require __DIR__ . '/_harness.php';

echo "=== connection_basics_test ===\n";
echo "Server construction, listen(), connect -> on('connection') fires, emit -> client receives, disconnect.\n";

$port = kislay_test_free_port();
$server = kislay_test_start_server('echo_server.php', $port);
$base = "http://127.0.0.1:$port";

try {
    // Engine.IO polling handshake: GET with no sid returns an open packet
    // "0{...}" containing a fresh sid. This alone proves Server::__construct()
    // and Server::listen() work.
    $resp = kislay_test_http_get("$base/socket.io/?EIO=4&transport=polling");
    kislay_test_assert($resp['code'] === 200, 'handshake GET returns 200');
    kislay_test_assert(str_starts_with($resp['body'], '0'), 'handshake body is an Engine.IO open packet ("0...")');
    $sid = kislay_test_extract_sid($resp['body']);
    kislay_test_assert($sid !== null && $sid !== '', 'handshake response contains a sid');

    // Socket.IO connect packet ("40") registers the client and should fire
    // on('connection'), which itself calls $client->reply('welcome', ...) -
    // this is the emit -> client receives half of the round trip.
    $resp = kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '40');
    kislay_test_assert($resp['code'] === 200, 'POST connect packet (40) returns 200');

    usleep(200000);
    $log = file_get_contents($server['log']);
    kislay_test_assert(str_contains($log, "connected $sid"), "on('connection') fired for $sid");

    // The connect ack ("0") and the welcome reply queued by on('connection')
    // should both be waiting for us on the next poll.
    $resp = kislay_test_http_get("$base/socket.io/?EIO=4&transport=polling&sid=$sid");
    kislay_test_assert($resp['code'] === 200, 'poll after connect returns 200');
    kislay_test_assert(str_contains($resp['body'], 'welcome'), 'poll body contains the welcome emit');
    kislay_test_assert(str_contains($resp['body'], $sid), 'welcome payload contains this client\'s id');

    // Custom event round trip: client sends 'chat', server's handler calls
    // Server::emit() to broadcast it back out.
    $pollChat = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '42["chat",{"message":"hi there"}]');
    $chatResult = kislay_test_reap_async_get($pollChat);
    kislay_test_assert(str_contains($chatResult['body'], 'hi there'), 'client received its own broadcast chat message');
    kislay_test_assert(str_contains($chatResult['body'], $sid), 'broadcast chat message identifies the sender');

    kislay_test_assert(kislay_test_is_alive($server), 'server process still alive after connect + emit round trip');

    // Unknown sid should be rejected, not crash the server.
    $resp = kislay_test_http_get("$base/socket.io/?EIO=4&transport=polling&sid=not-a-real-sid", 3.0);
    kislay_test_assert($resp['code'] === 400, 'GET with unknown sid returns 400 (not a hang/crash)');

    // Explicit disconnect ("1") should fire on('disconnect') and clean up
    // server-side bookkeeping.
    $resp = kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '1');
    kislay_test_assert($resp['code'] === 200, 'POST disconnect packet (1) returns 200');

    usleep(200000);
    $log = file_get_contents($server['log']);
    kislay_test_assert(str_contains($log, "disconnected $sid"), "on('disconnect') fired for $sid");

    $resp = kislay_test_http_get("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 3.0);
    kislay_test_assert($resp['code'] === 400, 'GET with disconnected sid returns 400 (session was removed)');

    kislay_test_assert(kislay_test_is_alive($server), 'server process still alive after disconnect');
    kislay_test_assert(kislay_test_detect_crash($server) === null, 'no crash signature in server log');
} finally {
    kislay_test_stop_server($server);
}

exit(kislay_test_summary());
