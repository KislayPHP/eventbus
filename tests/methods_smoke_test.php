<?php
require __DIR__ . '/_harness.php';

echo "=== methods_smoke_test ===\n";
echo "Every method CODEBASE_REVIEW.md flagged as documented-but-fatal: clientCount, roomCount,\n";
echo "getClients, setMaxPayload, onAuth, setThreads. Each must not fatal and must return something sane.\n";

$port = kislay_test_free_port();
// If any of methods_server.php's top-level setThreads()/setMaxPayload()/
// onAuth() calls fatal, the server process dies before listen() ever binds
// the port, and this start call itself throws/fails - that alone is a
// regression guard for the exact bug class CODEBASE_REVIEW.md flagged.
$server = kislay_test_start_server('methods_server.php', $port);
$base = "http://127.0.0.1:$port";

try {
    kislay_test_assert(kislay_test_is_alive($server), 'server started (setThreads/setMaxPayload/onAuth at startup did not fatal)');

    $sid = kislay_test_handshake($base);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '40');
    usleep(150000);

    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '42["subscribe",{"room":"probe-room"}]');
    usleep(100000);

    $poll = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '42["probe",null]');
    $result = kislay_test_reap_async_get($poll);

    kislay_test_assert(str_contains($result['body'], 'probe-result'), 'probe() round trip completed (clientCount/roomCount/getClients did not fatal)');
    kislay_test_assert(preg_match('/"clientCount":(\d+)/', $result['body'], $m) === 1, 'clientCount() returned a number');
    if (isset($m[1])) {
        kislay_test_assert((int)$m[1] >= 1, 'clientCount() >= 1 with one connected client');
    }
    kislay_test_assert(preg_match('/"roomCount":(\d+)/', $result['body'], $m2) === 1, 'roomCount() returned a number');
    if (isset($m2[1])) {
        kislay_test_assert((int)$m2[1] >= 1, 'roomCount() >= 1 after joining a room');
    }
    kislay_test_assert(str_contains($result['body'], $sid), 'getClients() included this client\'s sid');

    $poll2 = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '42["probe2",null]');
    $result2 = kislay_test_reap_async_get($poll2);

    kislay_test_assert(str_contains($result2['body'], 'probe2-result'), 'probe2() round trip completed (runtime setThreads/setMaxPayload/onAuth calls did not fatal)');
    kislay_test_assert(str_contains($result2['body'], '"setThreads":true'), 'setThreads() returned true');
    kislay_test_assert(str_contains($result2['body'], '"setMaxPayload":true'), 'setMaxPayload() returned true');
    kislay_test_assert(str_contains($result2['body'], '"onAuth":true'), 'onAuth() returned true');

    kislay_test_assert(kislay_test_is_alive($server), 'server process still alive');
    kislay_test_assert(kislay_test_detect_crash($server) === null, 'no crash signature in server log');
} finally {
    kislay_test_stop_server($server);
}

exit(kislay_test_summary());
