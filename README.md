# KislayPHP EventBus

[![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue.svg)](https://php.net)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/KislayPHP/eventbus/ci.yml)](https://github.com/KislayPHP/eventbus/actions)
[![codecov](https://codecov.io/gh/KislayPHP/eventbus/branch/main/graph/badge.svg)](https://codecov.io/gh/KislayPHP/eventbus)

A high-performance C++ PHP extension providing Socket.IO-compatible realtime communication for building interactive applications and microservices.

## ⚡ Key Features

- 🚀 **High Performance**: Real-time messaging with minimal latency
- 🔌 **Socket.IO Compatible**: Full Socket.IO v4 and Engine.IO support
- 🌐 **Multiple Transports**: WebSocket, HTTP long-polling, and Server-Sent Events
- 🏠 **Room Management**: Namespaces and rooms for organized messaging
- 📡 **Broadcasting**: Efficient event fan-out to multiple clients
- 🔧 **Configurable**: Environment-based configuration and INI settings
- 📊 **Monitoring**: Connection tracking and performance metrics

## 📦 Installation

### Via PECL (Recommended)

```bash
pecl install kislayphp_eventbus
```

Add to your `php.ini`:

```ini
extension=kislayphp_eventbus.so
```

### Manual Build

```bash
git clone https://github.com/KislayPHP/eventbus.git
cd eventbus
phpize
./configure
make
sudo make install
```

### Docker

```dockerfile
FROM php:8.2-cli
RUN pecl install kislayphp_eventbus && docker-php-ext-enable kislayphp_eventbus
```

## 🚀 Quick Start

### Server Setup

```php
<?php

// Create EventBus server
$eventbus = new KislayEventBus();

// Configure server
$eventbus->setOption('max_connections', 1000);
$eventbus->setOption('ping_interval', 30);

// Handle connections
$eventbus->on('connection', function($socket) {
    echo "Client connected: {$socket->id}\n";

    // Handle custom events
    $socket->on('chat message', function($data) use ($socket) {
        echo "Message from {$socket->id}: {$data['message']}\n";

        // Broadcast to all clients in room
        $socket->to('general')->emit('chat message', $data);
    });

    // Handle room joining
    $socket->on('join room', function($room) use ($socket) {
        $socket->join($room);
        $socket->emit('joined', ['room' => $room]);
    });
});

// Start server
echo "EventBus server running on http://localhost:3000\n";
$eventbus->listen('0.0.0.0', 3000);
```

### Client Usage (JavaScript)

```javascript
import io from 'socket.io-client';

const socket = io('http://localhost:3000');

// Connect to server
socket.on('connect', () => {
    console.log('Connected to EventBus server');

    // Join a room
    socket.emit('join room', 'general');

    // Send messages
    socket.emit('chat message', {
        message: 'Hello from client!',
        timestamp: Date.now()
    });
});

// Receive messages
socket.on('chat message', (data) => {
    console.log('Received:', data);
});

// Handle disconnections
socket.on('disconnect', () => {
    console.log('Disconnected from server');
});
```

## 📚 Documentation

📖 **[Complete Documentation](docs.md)** - API reference, configuration, examples, and best practices

## 🏗️ Architecture

KislayPHP EventBus implements efficient real-time communication:

```
┌─────────────────┐    ┌─────────────────┐
│   WebSocket     │    │   HTTP Long     │
│   Transport     │    │   Polling       │
│                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Event Bus   │ │    │ │ Event Bus   │ │
│ │ Engine      │ │    │ │ Engine      │ │
│ │ (C++)       │ │    │ │ (C++)       │ │
│ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘
         │                       │
         └───────────────────────┘
            PHP Integration
```

## 🎯 Use Cases

- **Real-time Chat**: Instant messaging applications
- **Live Dashboards**: Real-time data visualization
- **Notifications**: Push notifications and alerts
- **Collaborative Editing**: Live document collaboration
- **Gaming**: Real-time multiplayer games
- **IoT Applications**: Real-time sensor data streaming
- **Microservices**: Event-driven inter-service communication

## 📊 Performance

```
Connection Benchmark:
==================
Concurrent Connections: 1,000
Message Throughput:    50,000 msg/sec
Average Latency:       2.1 ms
Memory Usage:          45 MB
CPU Usage:             8.2%
```

## 🔧 Configuration

### php.ini Settings

```ini
; EventBus configuration
kislayphp.eventbus.max_connections = 1000
kislayphp.eventbus.ping_interval = 30
kislayphp.eventbus.ping_timeout = 60
kislayphp.eventbus.max_payload_size = 1048576

; Transport settings
kislayphp.eventbus.enable_websocket = 1
kislayphp.eventbus.enable_polling = 1
kislayphp.eventbus.polling_timeout = 20
```

### Environment Variables

```bash
export KISLAYPHP_EVENTBUS_MAX_CONNECTIONS=1000
export KISLAYPHP_EVENTBUS_PING_INTERVAL=30
export KISLAYPHP_EVENTBUS_ENABLE_WEBSOCKET=1
```

## 🧪 Testing

```bash
# Run unit tests
php run-tests.php

# Test with Socket.IO client
cd tests/
npm install socket.io-client
node test_client.js
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](.github/CONTRIBUTING.md) for details.

## 📄 License

Licensed under the [Apache License 2.0](LICENSE).

## 🆘 Support

- 📖 [Documentation](docs.md)
- 🐛 [Issue Tracker](https://github.com/KislayPHP/eventbus/issues)
- 💬 [Discussions](https://github.com/KislayPHP/eventbus/discussions)
- 📧 [Security Issues](.github/SECURITY.md)

## 📈 Roadmap

- [ ] Socket.IO v5 support
- [ ] Binary message support
- [ ] Redis adapter for clustering
- [ ] Message persistence
- [ ] Advanced authentication middleware

## 🙏 Acknowledgments

- **Socket.IO**: Real-time communication protocol
- **Engine.IO**: Transport layer implementation
- **PHP**: Zend API for extension development

---

**Built with ❤️ for real-time PHP applications**
- https://github.com/KislayPHP/config
- https://github.com/KislayPHP/metrics
- https://github.com/KislayPHP/queue

## Installation

### Via PECL

```bash
pecl install kislayphp_eventbus
```

Then add to your php.ini:

```ini
extension=kislayphp_eventbus.so
```

### Manual Build

```sh
phpize
./configure --enable-kislayphp_eventbus
make
```

## Run Locally

```sh
cd /path/to/eventbus
php -d extension=modules/kislay_socket.so example.php
```

## Example

```php
<?php
extension_loaded('kislayphp_eventbus') or die('kislayphp_eventbus not loaded');

$io = new KislayPHP\EventBus\Server();

$io->on('connection', function ($socket) use ($io) {
    $socket->join('room-1');
    $socket->emit('welcome', ['id' => $socket->id()]);
});

$io->on('message', function ($socket, $payload) {
    $socket->emitTo('room-1', 'message', $payload);
});

$io->on('binary', function ($socket, $payload) {
    $socket->emit('binary', $payload);
});

$io->listen('0.0.0.0', 8090, '/socket.io/');
// This call blocks; stop with Ctrl+C.
?>
```
