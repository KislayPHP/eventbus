<?php
require __DIR__ . '/_harness.php';

echo "=== alias_semantics_test ===\n";
echo "Documents current behavior: Server::emit()/publish()/send() are identical broadcast-to-everyone\n";
echo "aliases (per CODEBASE_REVIEW.md) - this test exists to catch a future accidental divergence.\n";

$port = kislay_test_free_port();
$server = kislay_test_start_server('alias_server.php', $port);
$base = "http://127.0.0.1:$port";

try {
    $sid = kislay_test_connect($base);

    $poll = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '42["trigger-emit",null]');
    $result = kislay_test_reap_async_get($poll);
    kislay_test_assert(str_contains($result['body'], 'via-emit') && str_contains($result['body'], '"from":"emit"'),
        'Server::emit() broadcasts to the connected client');

    $poll = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '42["trigger-publish",null]');
    $result = kislay_test_reap_async_get($poll);
    kislay_test_assert(str_contains($result['body'], 'via-publish') && str_contains($result['body'], '"from":"publish"'),
        'Server::publish() also broadcasts to the connected client (same as emit())');

    $poll = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '42["trigger-send",null]');
    $result = kislay_test_reap_async_get($poll);
    kislay_test_assert(str_contains($result['body'], 'via-send') && str_contains($result['body'], '"from":"send"'),
        'Server::send() also broadcasts to the connected client (same as emit())');

    kislay_test_assert(kislay_test_is_alive($server), 'server process still alive');
    kislay_test_assert(kislay_test_detect_crash($server) === null, 'no crash signature in server log');
} finally {
    kislay_test_stop_server($server);
}

exit(kislay_test_summary());
