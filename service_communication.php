<?php
// php -d extension=modules/kislayphp_eventbus.so service_communication.php

if (!extension_loaded('kislayphp_eventbus')) {
    fwrite(STDERR, "kislayphp_eventbus extension is not loaded\n");
    exit(1);
}

$bus = new Kislay\EventBus\Server();

$bus->on('connection', function ($socket) {
    $socket->join('svc.orders');
    $socket->join('svc.inventory');
});

// Request/reply style communication.
$bus->on('svc.request.inventory.reserve', function ($socket, $payload) {
    $requestId = is_array($payload) ? ($payload['requestId'] ?? '') : '';
    $traceId = is_array($payload) ? ($payload['traceId'] ?? '') : '';
    $socket->emit('svc.reply.inventory.reserve', [
        'requestId' => $requestId,
        'traceId' => $traceId,
        'status' => 'OK',
        'reserved' => true,
    ]);
});

// Domain event fan-out.
$bus->on('evt.orders.created', function ($socket, $payload) {
    $socket->emitTo('svc.inventory', 'evt.orders.created', $payload);
});

echo "EventBus service communication server listening on 0.0.0.0:8090\n";
$bus->listen('0.0.0.0', 8090, '/events/');
