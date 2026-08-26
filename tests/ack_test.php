<?php
require __DIR__ . '/_harness.php';

echo "=== ack_test ===\n";
echo "onWithAck(): an incoming EVENT packet carrying a Socket.IO ack id ('42<id>[...]') should get an\n";
echo "ACK packet back ('43<id>[retval]') iff the handler was registered via onWithAck(), not on().\n";

$port = kislay_test_free_port();
$server = kislay_test_start_server('ack_server.php', $port);
$base = "http://127.0.0.1:$port";

try {
    $sid = kislay_test_connect($base);

    // Wire format: engine.io "4" (message) + socket.io "2" (event) + ack id
    // digits ("1") + JSON array. No namespace prefix (default namespace).
    $poll = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 5.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '421["sum",{"a":2,"b":5}]');
    $result = kislay_test_reap_async_get($poll);

    kislay_test_assert(str_contains($result['body'], '431[7]'),
        'onWithAck() handler return value (2+5=7) came back as ACK packet "431[7]"');

    // Same shape, but sent with ack id "2" to an event registered via plain
    // on() (not onWithAck()) - must NOT produce an ACK packet, even though
    // the incoming packet carried an ack id and the handler returns a value.
    $poll2 = kislay_test_http_get_async("$base/socket.io/?EIO=4&transport=polling&sid=$sid", 2.0);
    usleep(100000);
    kislay_test_http_post("$base/socket.io/?EIO=4&transport=polling&sid=$sid", '422["echo-no-ack",{"x":1}]');
    $result2 = kislay_test_reap_async_get($poll2);

    kislay_test_assert(!str_contains($result2['body'], '432['),
        'plain on() handler does NOT send an ACK packet even when the incoming packet carried an ack id');

    kislay_test_assert(kislay_test_is_alive($server), 'server process still alive');
    kislay_test_assert(kislay_test_detect_crash($server) === null, 'no crash signature in server log');
} finally {
    kislay_test_stop_server($server);
}

exit(kislay_test_summary());
