<?php
require __DIR__ . '/_harness.php';

echo "=== namespace_test ===\n";
echo "Server::namespace() / Kislay\\EventBus\\EventNamespace - documented SUBSET implementation.\n";
echo "See docs.md for exact scope: namespace-prefixed on()/emit()/emitTo(), rooms shared across\n";
echo "namespaces, no per-namespace membership tracking for emit(). Default namespace behavior must\n";
echo "be byte-for-byte unaffected.\n";

$port = kislay_test_free_port();
$server = kislay_test_start_server('namespace_server.php', $port);
$base = "http://127.0.0.1:$port";

try {
    usleep(150000);
    $log = file_get_contents($server['log']);
    kislay_test_assert(str_contains($log, 'admin namespace name() = /admin'), 'EventNamespace::name() returns the namespace name with leading slash');

    // --- Default namespace: unaffected by namespace() existing at all ---
    $sidDefault = kislay_test_handshake($base);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sidDefault", '40');
    usleep(150000);
    $log = file_get_contents($server['log']);
    kislay_test_assert(str_contains($log, "default-ns connected $sidDefault"), "bare '40' still fires the default namespace's on('connection')");

    $poll = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sidDefault", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sidDefault", '42["ping"]');
    $result = kislay_test_reap_async_get($poll);
    kislay_test_assert(str_contains($result['body'], 'pong') && str_contains($result['body'], 'default'),
        "default namespace 'ping' handler still replies directly (unprefixed wire packet)");

    // --- Namespace-scoped connect: "40/admin," ---
    $sidAdmin = kislay_test_handshake($base);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sidAdmin", '40/admin,');
    usleep(150000);

    $resp = kislay_test_http_get("$base/socket.io/?EIO=4&transport=polling&sid=$sidAdmin");
    kislay_test_assert(str_contains($resp['body'], '40/admin,'), 'namespaced CONNECT gets an echoed "40/admin," ack packet');

    $log = file_get_contents($server['log']);
    kislay_test_assert(str_contains($log, "admin-ns connected $sidAdmin"), "namespaced CONNECT fires EventNamespace::on('connection') for '/admin', not the default namespace");
    kislay_test_assert(!str_contains($log, "default-ns connected $sidAdmin"), "namespaced CONNECT does NOT also fire the default namespace's on('connection')");

    // --- Namespace-scoped event: "42/admin,[...]" ---
    $poll = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sidAdmin", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sidAdmin", '42/admin,["ping"]');
    $result = kislay_test_reap_async_get($poll);
    kislay_test_assert(str_contains($result['body'], '/admin,') && str_contains($result['body'], 'pong'),
        "namespaced 'ping' handler's emit() comes back wire-prefixed with '/admin,'");

    kislay_test_assert(kislay_test_is_alive($server), 'server process still alive');
    kislay_test_assert(kislay_test_detect_crash($server) === null, 'no crash signature in server log');
} finally {
    kislay_test_stop_server($server);
}

exit(kislay_test_summary());
