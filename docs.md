# KislayPHP EventBus Extension Documentation

## Overview

The KislayPHP EventBus extension provides high-performance event-driven messaging with support for WebSocket connections, TCP sockets, and pluggable transport protocols. It enables real-time communication between services and clients with features like pub/sub messaging, event filtering, and connection management.

## Architecture

### Core Components
- **Event Publisher**: Publishes events to channels/topics
- **Event Subscriber**: Subscribes to channels and receives events
- **Transport Layer**: Pluggable transport protocols (WebSocket, TCP, HTTP)
- **Connection Manager**: Manages client connections and state
- **Event Router**: Routes events based on patterns and filters

### Transport Protocols
- **WebSocket**: Bidirectional real-time communication
- **TCP Socket**: Low-latency binary protocol
- **HTTP Long Polling**: Fallback for environments without WebSocket support
- **Server-Sent Events**: Unidirectional server-to-client events

## Installation

### Via PECL
```bash
pecl install kislayphp_eventbus
```

### Manual Build
```bash
cd kislayphp_eventbus/
phpize && ./configure --enable-kislayphp_eventbus && make && make install
```

### php.ini Configuration
```ini
extension=kislayphp_eventbus.so
```

## API Reference

### KislayPHP\\EventBus\\EventBus Class

The main event bus server class.

#### Constructor
```php
$eventBus = new KislayPHP\\EventBus\\EventBus(array $config = []);
```

#### Server Control
```php
$eventBus->start(): void
$eventBus->stop(): void
$eventBus->restart(): void
$eventBus->isRunning(): bool
```

#### Event Operations
```php
$eventBus->publish(string $channel, mixed $data, array $options = []): bool
$eventBus->subscribe(string $channel, callable $callback): bool
$eventBus->unsubscribe(string $channel): bool
```

#### Connection Management
```php
$eventBus->getConnections(): array
$eventBus->disconnect(string $connectionId): bool
$eventBus->broadcast(mixed $data, array $options = []): bool
```

### KislayPHP\\EventBus\\WebSocketServer Class

WebSocket server implementation.

#### Constructor
```php
$wsServer = new KislayPHP\\EventBus\\WebSocketServer(array $config = []);
```

#### WebSocket Operations
```php
$wsServer->onConnect(callable $callback): void
$wsServer->onMessage(callable $callback): void
$wsServer->onDisconnect(callable $callback): void
$wsServer->send(string $connectionId, mixed $data): bool
```

### KislayPHP\\EventBus\\Publisher Class

Event publisher client.

#### Constructor
```php
$publisher = new KislayPHP\\EventBus\\Publisher(string $host = 'localhost', int $port = 8080);
```

#### Publishing Events
```php
$publisher->publish(string $channel, mixed $data, array $options = []): bool
$publisher->publishAsync(string $channel, mixed $data, array $options = []): Promise
```

### KislayPHP\\EventBus\\Subscriber Class

Event subscriber client.

#### Constructor
```php
$subscriber = new KislayPHP\\EventBus\\Subscriber(string $host = 'localhost', int $port = 8080);
```

#### Subscribing to Events
```php
$subscriber->subscribe(string $channel, callable $callback): bool
$subscriber->unsubscribe(string $channel): bool
$subscriber->onError(callable $callback): void
```

## Usage Examples

### Basic WebSocket Event Bus
```php
<?php
use KislayPHP\\EventBus\\EventBus;

$eventBus = new EventBus([
    'host' => '0.0.0.0',
    'port' => 8080,
    'transports' => ['websocket', 'tcp']
]);

// Handle client connections
$eventBus->onConnect(function($connectionId, $transport) {
    echo "Client connected: $connectionId via $transport\n";
});

// Handle client disconnections
$eventBus->onDisconnect(function($connectionId) {
    echo "Client disconnected: $connectionId\n";
});

// Handle incoming messages
$eventBus->onMessage(function($connectionId, $data) {
    echo "Message from $connectionId: " . json_encode($data) . "\n";

    // Echo back to client
    $eventBus->send($connectionId, ['echo' => $data]);
});

// Start the event bus
$eventBus->start();
```

### Publish-Subscribe Pattern
```php
<?php
use KislayPHP\\EventBus\\Publisher;
use KislayPHP\\EventBus\\Subscriber;

// Publisher
$publisher = new Publisher('localhost', 8080);

// Subscriber
$subscriber = new Subscriber('localhost', 8080);

// Subscribe to channels
$subscriber->subscribe('user_events', function($data) {
    echo "User event received: " . json_encode($data) . "\n";

    // Process user event
    processUserEvent($data);
});

$subscriber->subscribe('order_updates', function($data) {
    echo "Order update: " . json_encode($data) . "\n";

    // Update order status
    updateOrderStatus($data);
});

// Handle connection errors
$subscriber->onError(function($error) {
    echo "Connection error: $error\n";
});

// Publish events
$publisher->publish('user_events', [
    'event' => 'user_registered',
    'user_id' => 12345,
    'timestamp' => time()
]);

$publisher->publish('order_updates', [
    'order_id' => 'ORD-001',
    'status' => 'shipped',
    'tracking_number' => '1Z999AA1234567890'
]);

function processUserEvent(array $data): void {
    // Handle user registration
    echo "Processing user registration for ID: {$data['user_id']}\n";
}

function updateOrderStatus(array $data): void {
    // Update order status in database
    echo "Updating order {$data['order_id']} to status: {$data['status']}\n";
}
```

### Real-time Chat Application
```php
<?php
use KislayPHP\\EventBus\\EventBus;

class ChatServer {
    private $eventBus;
    private $rooms = [];

    public function __construct() {
        $this->eventBus = new EventBus([
            'host' => '0.0.0.0',
            'port' => 8080
        ]);

        $this->setupEventHandlers();
    }

    private function setupEventHandlers(): void {
        $this->eventBus->onConnect(function($connectionId) {
            echo "User connected: $connectionId\n";
        });

        $this->eventBus->onDisconnect(function($connectionId) {
            $this->leaveAllRooms($connectionId);
            echo "User disconnected: $connectionId\n";
        });

        $this->eventBus->onMessage(function($connectionId, $data) {
            $this->handleMessage($connectionId, $data);
        });
    }

    private function handleMessage(string $connectionId, array $data): void {
        $action = $data['action'] ?? '';

        switch ($action) {
            case 'join_room':
                $this->joinRoom($connectionId, $data['room']);
                break;

            case 'leave_room':
                $this->leaveRoom($connectionId, $data['room']);
                break;

            case 'send_message':
                $this->sendMessage($connectionId, $data['room'], $data['message']);
                break;

            case 'private_message':
                $this->sendPrivateMessage($connectionId, $data['to'], $data['message']);
                break;
        }
    }

    private function joinRoom(string $connectionId, string $room): void {
        if (!isset($this->rooms[$room])) {
            $this->rooms[$room] = [];
        }

        $this->rooms[$room][] = $connectionId;

        // Notify room members
        $this->broadcastToRoom($room, [
            'action' => 'user_joined',
            'user' => $connectionId,
            'room' => $room,
            'timestamp' => time()
        ], $connectionId);

        // Send room info to user
        $this->eventBus->send($connectionId, [
            'action' => 'room_joined',
            'room' => $room,
            'members' => $this->rooms[$room]
        ]);
    }

    private function leaveRoom(string $connectionId, string $room): void {
        if (isset($this->rooms[$room])) {
            $index = array_search($connectionId, $this->rooms[$room]);
            if ($index !== false) {
                unset($this->rooms[$room][$index]);
                $this->rooms[$room] = array_values($this->rooms[$room]);

                // Notify room members
                $this->broadcastToRoom($room, [
                    'action' => 'user_left',
                    'user' => $connectionId,
                    'room' => $room,
                    'timestamp' => time()
                ]);
            }
        }
    }

    private function sendMessage(string $connectionId, string $room, string $message): void {
        $this->broadcastToRoom($room, [
            'action' => 'message',
            'from' => $connectionId,
            'room' => $room,
            'message' => $message,
            'timestamp' => time()
        ], $connectionId);
    }

    private function sendPrivateMessage(string $connectionId, string $to, string $message): void {
        $this->eventBus->send($to, [
            'action' => 'private_message',
            'from' => $connectionId,
            'message' => $message,
            'timestamp' => time()
        ]);
    }

    private function broadcastToRoom(string $room, array $data, string $exclude = null): void {
        if (!isset($this->rooms[$room])) {
            return;
        }

        foreach ($this->rooms[$room] as $memberId) {
            if ($memberId !== $exclude) {
                $this->eventBus->send($memberId, $data);
            }
        }
    }

    private function leaveAllRooms(string $connectionId): void {
        foreach ($this->rooms as $room => $members) {
            if (in_array($connectionId, $members)) {
                $this->leaveRoom($connectionId, $room);
            }
        }
    }

    public function start(): void {
        $this->eventBus->start();
    }
}

// Usage
$chatServer = new ChatServer();
$chatServer->start();
```

### Event Filtering and Routing
```php
<?php
use KislayPHP\\EventBus\\EventBus;
use KislayPHP\\EventBus\\EventFilter;

class AdvancedEventBus extends EventBus {
    private $filters = [];
    private $routes = [];

    public function addFilter(string $channel, EventFilter $filter): void {
        if (!isset($this->filters[$channel])) {
            $this->filters[$channel] = [];
        }
        $this->filters[$channel][] = $filter;
    }

    public function addRoute(string $pattern, callable $handler): void {
        $this->routes[$pattern] = $handler;
    }

    protected function processMessage(string $connectionId, array $data): void {
        $channel = $data['channel'] ?? 'default';

        // Apply filters
        if (!$this->passesFilters($channel, $data)) {
            return;
        }

        // Route message
        $this->routeMessage($channel, $data, $connectionId);
    }

    private function passesFilters(string $channel, array $data): bool {
        if (!isset($this->filters[$channel])) {
            return true;
        }

        foreach ($this->filters[$channel] as $filter) {
            if (!$filter->matches($data)) {
                return false;
            }
        }

        return true;
    }

    private function routeMessage(string $channel, array $data, string $connectionId): void {
        foreach ($this->routes as $pattern => $handler) {
            if (fnmatch($pattern, $channel)) {
                $handler($data, $connectionId);
                break;
            }
        }
    }
}

class EventFilter {
    private $conditions = [];

    public function where(string $field, $value, string $operator = '='): self {
        $this->conditions[] = [
            'field' => $field,
            'value' => $value,
            'operator' => $operator
        ];
        return $this;
    }

    public function matches(array $data): bool {
        foreach ($this->conditions as $condition) {
            $field = $condition['field'];
            $expectedValue = $condition['value'];
            $operator = $condition['operator'];

            $actualValue = $this->getNestedValue($data, $field);

            if (!$this->compareValues($actualValue, $expectedValue, $operator)) {
                return false;
            }
        }

        return true;
    }

    private function getNestedValue(array $data, string $field) {
        $keys = explode('.', $field);
        $value = $data;

        foreach ($keys as $key) {
            if (!isset($value[$key])) {
                return null;
            }
            $value = $value[$key];
        }

        return $value;
    }

    private function compareValues($actual, $expected, string $operator): bool {
        switch ($operator) {
            case '=':
                return $actual == $expected;
            case '!=':
                return $actual != $expected;
            case '>':
                return $actual > $expected;
            case '<':
                return $actual < $expected;
            case '>=':
                return $actual >= $expected;
            case '<=':
                return $actual <= $expected;
            case 'in':
                return in_array($actual, (array)$expected);
            case 'contains':
                return strpos($actual, $expected) !== false;
            default:
                return false;
        }
    }
}

// Usage
$eventBus = new AdvancedEventBus([
    'host' => '0.0.0.0',
    'port' => 8080
]);

// Add filters
$userEventFilter = (new EventFilter())
    ->where('user.type', 'premium')
    ->where('event.priority', 'high', '>=');

$eventBus->addFilter('user_events', $userEventFilter);

// Add routes
$eventBus->addRoute('user_*', function($data, $connectionId) {
    echo "User event: " . json_encode($data) . "\n";
});

$eventBus->addRoute('order_*', function($data, $connectionId) {
    echo "Order event: " . json_encode($data) . "\n";
});

$eventBus->start();
```

### TCP Socket Transport
```php
<?php
use KislayPHP\\EventBus\\TCPServer;

$tcpServer = new TCPServer([
    'host' => '0.0.0.0',
    'port' => 9090
]);

$tcpServer->onConnect(function($connectionId) {
    echo "TCP client connected: $connectionId\n";

    // Send welcome message
    $tcpServer->send($connectionId, "Welcome to KislayPHP EventBus TCP Server\n");
});

$tcpServer->onMessage(function($connectionId, $data) {
    echo "TCP message from $connectionId: $data\n";

    // Echo back
    $tcpServer->send($connectionId, "Echo: $data");
});

$tcpServer->onDisconnect(function($connectionId) {
    echo "TCP client disconnected: $connectionId\n";
});

// Start TCP server
$tcpServer->start();
```

### Client Libraries

#### JavaScript WebSocket Client
```javascript
class EventBusClient {
    constructor(url = 'ws://localhost:8080') {
        this.url = url;
        this.ws = null;
        this.subscriptions = new Map();
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectInterval = 1000;
    }

    connect() {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.url);

            this.ws.onopen = () => {
                console.log('Connected to EventBus');
                this.reconnectAttempts = 0;
                resolve();
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            };

            this.ws.onclose = () => {
                console.log('Disconnected from EventBus');
                this.handleReconnect();
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                reject(error);
            };
        });
    }

    handleMessage(data) {
        const { channel, payload } = data;

        if (this.subscriptions.has(channel)) {
            const callbacks = this.subscriptions.get(channel);
            callbacks.forEach(callback => callback(payload));
        }
    }

    handleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

            setTimeout(() => {
                this.connect().catch(() => {
                    this.handleReconnect();
                });
            }, this.reconnectInterval * this.reconnectAttempts);
        }
    }

    subscribe(channel, callback) {
        if (!this.subscriptions.has(channel)) {
            this.subscriptions.set(channel, []);
        }

        this.subscriptions.get(channel).push(callback);

        // Send subscription message
        this.send({
            action: 'subscribe',
            channel: channel
        });
    }

    unsubscribe(channel) {
        this.subscriptions.delete(channel);

        // Send unsubscription message
        this.send({
            action: 'unsubscribe',
            channel: channel
        });
    }

    publish(channel, data) {
        this.send({
            action: 'publish',
            channel: channel,
            data: data
        });
    }

    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        }
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Usage
const client = new EventBusClient('ws://localhost:8080');

client.connect().then(() => {
    // Subscribe to channels
    client.subscribe('chat_room_1', (message) => {
        console.log('New message:', message);
        displayMessage(message);
    });

    client.subscribe('notifications', (notification) => {
        console.log('Notification:', notification);
        showNotification(notification);
    });

    // Publish messages
    client.publish('chat_room_1', {
        user: 'john_doe',
        message: 'Hello everyone!',
        timestamp: Date.now()
    });
});

function displayMessage(message) {
    const chatDiv = document.getElementById('chat');
    const messageDiv = document.createElement('div');
    messageDiv.textContent = `${message.user}: ${message.message}`;
    chatDiv.appendChild(messageDiv);
}

function showNotification(notification) {
    // Show notification to user
    alert(notification.message);
}
```

#### Python Client
```python
import asyncio
import websockets
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EventBusClient:
    def __init__(self, uri='ws://localhost:8080'):
        self.uri = uri
        self.websocket = None
        self.subscriptions = {}
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5

    async def connect(self):
        try:
            self.websocket = await websockets.connect(self.uri)
            logger.info("Connected to EventBus")
            self.reconnect_attempts = 0
            await self.listen()
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            await self.handle_reconnect()

    async def listen(self):
        try:
            async for message in self.websocket:
                data = json.loads(message)
                await self.handle_message(data)
        except Exception as e:
            logger.error(f"Listen error: {e}")
            await self.handle_reconnect()

    async def handle_message(self, data):
        channel = data.get('channel')
        payload = data.get('payload', data)

        if channel in self.subscriptions:
            for callback in self.subscriptions[channel]:
                await callback(payload)

    async def handle_reconnect(self):
        if self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            delay = 1 * self.reconnect_attempts
            logger.info(f"Reconnecting in {delay} seconds (attempt {self.reconnect_attempts})")
            await asyncio.sleep(delay)
            await self.connect()

    def subscribe(self, channel, callback):
        if channel not in self.subscriptions:
            self.subscriptions[channel] = []
        self.subscriptions[channel].append(callback)

        # Send subscription message
        asyncio.create_task(self.send({
            'action': 'subscribe',
            'channel': channel
        }))

    def unsubscribe(self, channel):
        if channel in self.subscriptions:
            del self.subscriptions[channel]

        # Send unsubscription message
        asyncio.create_task(self.send({
            'action': 'unsubscribe',
            'channel': channel
        }))

    async def publish(self, channel, data):
        await self.send({
            'action': 'publish',
            'channel': channel,
            'data': data
        })

    async def send(self, data):
        if self.websocket:
            try:
                await self.websocket.send(json.dumps(data))
            except Exception as e:
                logger.error(f"Send error: {e}")

    async def close(self):
        if self.websocket:
            await self.websocket.close()

# Usage
async def main():
    client = EventBusClient('ws://localhost:8080')

    # Connect to server
    await client.connect()

    # Subscribe to channels
    def handle_chat_message(message):
        print(f"Chat: {message['user']}: {message['text']}")

    def handle_notification(notification):
        print(f"Notification: {notification['title']} - {notification['message']}")

    client.subscribe('chat', handle_chat_message)
    client.subscribe('notifications', handle_notification)

    # Publish messages
    await client.publish('chat', {
        'user': 'python_client',
        'text': 'Hello from Python!',
        'timestamp': asyncio.get_event_loop().time()
    })

    # Keep connection alive
    await asyncio.Future()

if __name__ == '__main__':
    asyncio.run(main())
```

## Advanced Usage

### Event Persistence and Replay
```php
<?php
use KislayPHP\\EventBus\\EventBus;
use KislayPHP\\EventBus\\EventStore;

class PersistentEventBus extends EventBus {
    private $eventStore;

    public function __construct(array $config = []) {
        parent::__construct($config);
        $this->eventStore = new EventStore($config['storage'] ?? 'memory');
    }

    public function publish(string $channel, $data, array $options = []): bool {
        // Store event before publishing
        $eventId = $this->eventStore->store($channel, $data, $options);

        // Add event ID to options
        $options['event_id'] = $eventId;

        return parent::publish($channel, $data, $options);
    }

    public function replayEvents(string $channel, callable $callback, int $fromEventId = 0): void {
        $events = $this->eventStore->getEvents($channel, $fromEventId);

        foreach ($events as $event) {
            $callback($event['data'], $event['options']);
        }
    }

    public function getEventHistory(string $channel, int $limit = 100): array {
        return $this->eventStore->getEvents($channel, 0, $limit);
    }
}

class EventStore {
    private $storage;

    public function __construct(string $storageType = 'memory') {
        switch ($storageType) {
            case 'redis':
                $this->storage = new RedisEventStorage();
                break;
            case 'database':
                $this->storage = new DatabaseEventStorage();
                break;
            default:
                $this->storage = new MemoryEventStorage();
        }
    }

    public function store(string $channel, $data, array $options = []): int {
        return $this->storage->store($channel, $data, $options);
    }

    public function getEvents(string $channel, int $fromEventId = 0, int $limit = 100): array {
        return $this->storage->getEvents($channel, $fromEventId, $limit);
    }
}

class MemoryEventStorage {
    private $events = [];
    private $nextId = 1;

    public function store(string $channel, $data, array $options = []): int {
        $eventId = $this->nextId++;
        $this->events[$channel][] = [
            'id' => $eventId,
            'data' => $data,
            'options' => $options,
            'timestamp' => time()
        ];
        return $eventId;
    }

    public function getEvents(string $channel, int $fromEventId = 0, int $limit = 100): array {
        if (!isset($this->events[$channel])) {
            return [];
        }

        $events = array_filter($this->events[$channel], function($event) use ($fromEventId) {
            return $event['id'] > $fromEventId;
        });

        return array_slice($events, 0, $limit);
    }
}

// Usage
$eventBus = new PersistentEventBus([
    'host' => '0.0.0.0',
    'port' => 8080,
    'storage' => 'memory'
]);

// Publish events (they are automatically stored)
$eventBus->publish('user_actions', [
    'user_id' => 123,
    'action' => 'login',
    'timestamp' => time()
]);

// Replay events for new subscribers
$eventBus->onConnect(function($connectionId) {
    // Send recent events to new connections
    $eventBus->replayEvents('user_actions', function($data) use ($connectionId) {
        $eventBus->send($connectionId, [
            'channel' => 'user_actions',
            'payload' => $data
        ]);
    });
});
```

### Event Transformation and Enrichment
```php
<?php
use KislayPHP\\EventBus\\EventBus;

class TransformingEventBus extends EventBus {
    private $transformers = [];

    public function addTransformer(string $channel, callable $transformer): void {
        if (!isset($this->transformers[$channel])) {
            $this->transformers[$channel] = [];
        }
        $this->transformers[$channel][] = $transformer;
    }

    protected function processEvent(string $channel, $data, array $options = []): mixed {
        // Apply transformers
        $transformedData = $this->applyTransformers($channel, $data);

        return parent::processEvent($channel, $transformedData, $options);
    }

    private function applyTransformers(string $channel, $data) {
        if (!isset($this->transformers[$channel])) {
            return $data;
        }

        foreach ($this->transformers[$channel] as $transformer) {
            $data = $transformer($data);
        }

        return $data;
    }
}

// Usage
$eventBus = new TransformingEventBus([
    'host' => '0.0.0.0',
    'port' => 8080
]);

// Add data enrichment transformer
$eventBus->addTransformer('user_events', function($data) {
    // Enrich user data with additional information
    if (isset($data['user_id'])) {
        $userInfo = getUserInfo($data['user_id']);
        $data['user_info'] = $userInfo;
    }

    // Add processing timestamp
    $data['processed_at'] = time();

    return $data;
});

// Add data validation transformer
$eventBus->addTransformer('user_events', function($data) {
    // Validate required fields
    if (!isset($data['user_id']) || !isset($data['action'])) {
        throw new Exception('Invalid user event data');
    }

    // Sanitize data
    $data['action'] = strtolower(trim($data['action']));

    return $data;
});

// Add data filtering transformer
$eventBus->addTransformer('user_events', function($data) {
    // Filter out sensitive information
    unset($data['password']);
    unset($data['credit_card']);

    return $data;
});

function getUserInfo(int $userId): array {
    // Fetch user information from database
    return [
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'role' => 'user'
    ];
}
```

### Clustering and High Availability
```php
<?php
use KislayPHP\\EventBus\\ClusteredEventBus;

class ClusteredEventBus extends EventBus {
    private $clusterNodes = [];
    private $nodeId;
    private $gossipProtocol;

    public function __construct(array $config = []) {
        parent::__construct($config);
        $this->nodeId = $config['node_id'] ?? uniqid('node_', true);
        $this->gossipProtocol = new GossipProtocol($this->nodeId);
        $this->setupClustering();
    }

    private function setupClustering(): void {
        // Join cluster
        $this->gossipProtocol->joinCluster($this->clusterNodes);

        // Handle cluster events
        $this->gossipProtocol->onNodeJoin(function($nodeId) {
            echo "Node joined cluster: $nodeId\n";
            $this->syncStateWithNode($nodeId);
        });

        $this->gossipProtocol->onNodeLeave(function($nodeId) {
            echo "Node left cluster: $nodeId\n";
            $this->redistributeConnections($nodeId);
        });
    }

    public function publish(string $channel, $data, array $options = []): bool {
        // Publish locally
        $localResult = parent::publish($channel, $data, $options);

        // Publish to cluster nodes
        $clusterResult = $this->publishToCluster($channel, $data, $options);

        return $localResult && $clusterResult;
    }

    private function publishToCluster(string $channel, $data, array $options = []): bool {
        $successCount = 0;

        foreach ($this->clusterNodes as $node) {
            try {
                $this->sendToNode($node, 'publish', [
                    'channel' => $channel,
                    'data' => $data,
                    'options' => $options
                ]);
                $successCount++;
            } catch (Exception $e) {
                echo "Failed to publish to node {$node['id']}: {$e->getMessage()}\n";
            }
        }

        // Quorum-based success (majority of nodes)
        return $successCount >= ceil(count($this->clusterNodes) / 2);
    }

    private function syncStateWithNode(string $nodeId): void {
        // Sync subscriptions, connections, etc.
        $state = $this->getClusterState();
        $this->sendToNode($this->getNodeById($nodeId), 'sync_state', $state);
    }

    private function redistributeConnections(string $nodeId): void {
        // Redistribute connections from failed node
        $connections = $this->getConnectionsForNode($nodeId);

        foreach ($connections as $connection) {
            $newNode = $this->selectBestNodeForConnection($connection);
            $this->migrateConnection($connection, $newNode);
        }
    }

    private function getClusterState(): array {
        return [
            'subscriptions' => $this->getAllSubscriptions(),
            'connections' => $this->getAllConnections(),
            'node_id' => $this->nodeId
        ];
    }

    private function selectBestNodeForConnection($connection): array {
        // Select node with least connections
        $bestNode = null;
        $minConnections = PHP_INT_MAX;

        foreach ($this->clusterNodes as $node) {
            if ($node['connection_count'] < $minConnections) {
                $minConnections = $node['connection_count'];
                $bestNode = $node;
            }
        }

        return $bestNode;
    }
}

// Usage
$clusteredBus = new ClusteredEventBus([
    'host' => '0.0.0.0',
    'port' => 8080,
    'node_id' => 'node_1',
    'cluster_nodes' => [
        ['host' => 'node2.example.com', 'port' => 8080],
        ['host' => 'node3.example.com', 'port' => 8080]
    ]
]);

$clusteredBus->start();
```

## Integration Examples

### Laravel Broadcasting Integration
```php
<?php
// config/broadcasting.php
'connections' => [
    'kislayphp' => [
        'driver' => 'kislayphp',
        'host' => env('EVENTBUS_HOST', 'localhost'),
        'port' => env('EVENTBUS_PORT', 8080),
    ],
],

// app/Broadcasting/KislayPHPBroadcaster.php
class KislayPHPBroadcaster implements Illuminate\\Broadcasting\\Broadcasters\\Broadcaster {
    private $publisher;

    public function __construct() {
        $this->publisher = new KislayPHP\\EventBus\\Publisher(
            config('broadcasting.connections.kislayphp.host'),
            config('broadcasting.connections.kislayphp.port')
        );
    }

    public function broadcast(array $channels, $event, array $payload = []): void {
        $data = [
            'event' => $event,
            'data' => $payload,
            'timestamp' => now()->timestamp
        ];

        foreach ($channels as $channel) {
            $this->publisher->publish($channel, $data);
        }
    }

    public function auth($request): mixed {
        // Authentication logic
        return null;
    }

    public function validAuthenticationResponse($request, $result): mixed {
        return null;
    }
}

// In EventServiceProvider
Broadcast::extend('kislayphp', function($app, $config) {
    return new KislayPHPBroadcaster();
});
```

### Symfony Messenger Integration
```php
<?php
// src/Messenger/Transport/KislayPHPTransport.php
class KislayPHPTransport implements Symfony\\Component\\Messenger\\Transport\\TransportInterface {
    private $publisher;
    private $subscriber;

    public function __construct(string $host = 'localhost', int $port = 8080) {
        $this->publisher = new KislayPHP\\EventBus\\Publisher($host, $port);
        $this->subscriber = new KislayPHP\\EventBus\\Subscriber($host, $port);
    }

    public function get(): iterable {
        // This would need to be implemented differently for pull-based consumption
        // For now, return empty (push-based consumption would be handled via callbacks)
        return [];
    }

    public function ack(Envelope $envelope): void {
        // Auto-ack since EventBus handles delivery
    }

    public function reject(Envelope $envelope): void {
        // Handle rejection (could republish to error channel)
        $this->publisher->publish('messenger_errors', [
            'envelope' => serialize($envelope),
            'error' => 'Message rejected'
        ]);
    }

    public function send(Envelope $envelope): void {
        $channel = $this->getChannelFromEnvelope($envelope);
        $this->publisher->publish($channel, serialize($envelope));
    }

    private function getChannelFromEnvelope(Envelope $envelope): string {
        // Extract channel from envelope stamps
        foreach ($envelope->all() as $stamp) {
            if ($stamp instanceof ChannelStamp) {
                return $stamp->getChannel();
            }
        }
        return 'default';
    }

    public function subscribe(string $channel, callable $handler): void {
        $this->subscriber->subscribe($channel, function($data) use ($handler) {
            $envelope = unserialize($data);
            $handler($envelope);
        });
    }
}

// config/packages/messenger.yaml
framework:
    messenger:
        transports:
            kislayphp: '%env(MESSENGER_TRANSPORT_DSN)%'

        routing:
            'App\\Message\\AsyncMessage': kislayphp
```

## Testing

### Unit Testing
```php
<?php
use PHPUnit\\Framework\\TestCase;
use KislayPHP\\EventBus\\EventBus;

class EventBusTest extends TestCase {
    private $eventBus;

    protected function setUp(): void {
        $this->eventBus = new EventBus([
            'host' => '127.0.0.1',
            'port' => 0 // Random port for testing
        ]);
    }

    public function testPublishSubscribe(): void {
        $receivedMessages = [];

        $this->eventBus->subscribe('test_channel', function($data) use (&$receivedMessages) {
            $receivedMessages[] = $data;
        });

        $testData = ['message' => 'test', 'timestamp' => time()];
        $this->eventBus->publish('test_channel', $testData);

        // Allow async processing
        usleep(100000); // 100ms

        $this->assertCount(1, $receivedMessages);
        $this->assertEquals($testData, $receivedMessages[0]);
    }

    public function testMultipleSubscribers(): void {
        $subscriber1Messages = [];
        $subscriber2Messages = [];

        $this->eventBus->subscribe('broadcast', function($data) use (&$subscriber1Messages) {
            $subscriber1Messages[] = $data;
        });

        $this->eventBus->subscribe('broadcast', function($data) use (&$subscriber2Messages) {
            $subscriber2Messages[] = $data;
        });

        $this->eventBus->publish('broadcast', 'test message');

        usleep(100000);

        $this->assertEquals(['test message'], $subscriber1Messages);
        $this->assertEquals(['test message'], $subscriber2Messages);
    }

    public function testUnsubscribe(): void {
        $messages = [];

        $callback = function($data) use (&$messages) {
            $messages[] = $data;
        };

        $this->eventBus->subscribe('test', $callback);
        $this->eventBus->publish('test', 'message1');
        usleep(50000);

        $this->eventBus->unsubscribe('test');
        $this->eventBus->publish('test', 'message2');
        usleep(50000);

        $this->assertEquals(['message1'], $messages);
    }
}
```

### Integration Testing
```php
<?php
class EventBusIntegrationTest extends PHPUnit\\Framework\\TestCase {
    private static $server;
    private static $port = 9090;

    public static function setUpBeforeClass(): void {
        self::$server = new KislayPHP\\EventBus\\EventBus([
            'host' => '127.0.0.1',
            'port' => self::$port
        ]);
        self::$server->start();
        sleep(1); // Allow server to start
    }

    public static function tearDownAfterClass(): void {
        if (self::$server) {
            self::$server->stop();
        }
    }

    public function testWebSocketConnection(): void {
        $client = new KislayPHP\\EventBus\\Publisher('127.0.0.1', self::$port);
        $received = [];

        // This is a simplified test - in practice you'd need a WebSocket client
        $this->assertTrue($client->publish('test', ['data' => 'integration test']));
    }

    public function testTCPConnection(): void {
        $tcpClient = new KislayPHP\\EventBus\\TCPClient('127.0.0.1', self::$port + 1); // Assuming TCP port

        $this->assertTrue($tcpClient->connect());
        $this->assertTrue($tcpClient->send(['action' => 'ping']));
        $tcpClient->disconnect();
    }

    public function testLoadTest(): void {
        $publisher = new KislayPHP\\EventBus\\Publisher('127.0.0.1', self::$port);
        $start = microtime(true);

        // Publish 1000 messages
        for ($i = 0; $i < 1000; $i++) {
            $publisher->publish('load_test', ['id' => $i, 'data' => str_repeat('x', 100)]);
        }

        $duration = microtime(true) - $start;
        $throughput = 1000 / $duration;

        $this->assertGreaterThan(100, $throughput); // At least 100 messages/second
        echo "Throughput: " . round($throughput, 2) . " msg/sec\n";
    }
}
```

### Mock EventBus for Testing
```php
<?php
class MockEventBus extends KislayPHP\\EventBus\\EventBus {
    private $publishedMessages = [];
    private $subscriptions = [];

    public function publish(string $channel, $data, array $options = []): bool {
        $this->publishedMessages[] = [
            'channel' => $channel,
            'data' => $data,
            'options' => $options,
            'timestamp' => time()
        ];

        // Trigger subscribers
        if (isset($this->subscriptions[$channel])) {
            foreach ($this->subscriptions[$channel] as $callback) {
                $callback($data);
            }
        }

        return true;
    }

    public function subscribe(string $channel, callable $callback): bool {
        if (!isset($this->subscriptions[$channel])) {
            $this->subscriptions[$channel] = [];
        }
        $this->subscriptions[$channel][] = $callback;
        return true;
    }

    public function getPublishedMessages(string $channel = null): array {
        if ($channel) {
            return array_filter($this->publishedMessages, function($msg) use ($channel) {
                return $msg['channel'] === $channel;
            });
        }
        return $this->publishedMessages;
    }

    public function getSubscriptions(): array {
        return $this->subscriptions;
    }

    public function clear(): void {
        $this->publishedMessages = [];
        $this->subscriptions = [];
    }
}

// Usage in tests
class ChatServiceTest extends TestCase {
    private $eventBus;
    private $chatService;

    protected function setUp(): void {
        $this->eventBus = new MockEventBus();
        $this->chatService = new ChatService($this->eventBus);
    }

    public function testSendMessage(): void {
        $this->chatService->sendMessage('room1', 'user1', 'Hello world!');

        $messages = $this->eventBus->getPublishedMessages('chat_room1');
        $this->assertCount(1, $messages);

        $message = $messages[0];
        $this->assertEquals('user1', $message['data']['user']);
        $this->assertEquals('Hello world!', $message['data']['message']);
    }

    public function testJoinRoom(): void {
        $this->chatService->joinRoom('user1', 'room1');

        $messages = $this->eventBus->getPublishedMessages('room_joins');
        $this->assertCount(1, $messages);
        $this->assertEquals('user1', $messages[0]['data']['user']);
        $this->assertEquals('room1', $messages[0]['data']['room']);
    }
}
```

## Troubleshooting

### Common Issues

#### Connection Failures
**Symptoms:** Clients unable to connect to EventBus server

**Solutions:**
1. Check server host and port configuration
2. Verify firewall settings allow connections
3. Check server logs for binding errors
4. Ensure server is actually running

#### Message Loss
**Symptoms:** Published messages not received by subscribers

**Solutions:**
1. Verify channel names match between publishers and subscribers
2. Check network connectivity between clients and server
3. Monitor server logs for message processing errors
4. Implement message acknowledgments for critical messages

#### Performance Degradation
**Symptoms:** High latency or low throughput

**Solutions:**
1. Monitor connection count and resource usage
2. Implement connection pooling
3. Use appropriate transport protocol (WebSocket vs TCP)
4. Scale horizontally with multiple server instances

### Performance Tuning

#### Connection Management
```php
<?php
class OptimizedEventBus extends EventBus {
    private $maxConnections = 10000;
    private $connectionTimeout = 300; // 5 minutes
    private $heartbeatInterval = 30; // 30 seconds

    protected function setupConnectionManagement(): void {
        $this->startHeartbeatChecker();
        $this->startConnectionLimiter();
    }

    private function startHeartbeatChecker(): void {
        // Periodically check for dead connections
        $this->timer(function() {
            $now = time();
            $connections = $this->getConnections();

            foreach ($connections as $id => $connection) {
                if (($now - $connection['last_activity']) > $this->connectionTimeout) {
                    $this->disconnect($id);
                }
            }
        }, $this->heartbeatInterval);
    }

    private function startConnectionLimiter(): void {
        $this->onConnect(function($connectionId) {
            $activeConnections = count($this->getConnections());

            if ($activeConnections > $this->maxConnections) {
                $this->send($connectionId, ['error' => 'Connection limit exceeded']);
                $this->disconnect($connectionId);
                return false;
            }

            return true;
        });
    }

    protected function updateConnectionActivity(string $connectionId): void {
        // Update last activity timestamp
        $this->connections[$connectionId]['last_activity'] = time();
    }
}
```

#### Monitoring and Metrics
```php
<?php
class MonitoredEventBus extends EventBus {
    private $metrics;

    public function __construct(array $config = []) {
        parent::__construct($config);
        $this->metrics = new KislayPHP\\Metrics\\Metrics();
    }

    public function publish(string $channel, $data, array $options = []): bool {
        $start = microtime(true);
        $result = parent::publish($channel, $data, $options);
        $duration = microtime(true) - $start;

        $this->metrics->increment('eventbus_messages_published_total');
        $this->metrics->histogram('eventbus_publish_duration_seconds', $duration);

        if (!$result) {
            $this->metrics->increment('eventbus_publish_errors_total');
        }

        return $result;
    }

    public function onConnect(callable $callback): void {
        parent::onConnect(function($connectionId, $transport) use ($callback) {
            $this->metrics->increment('eventbus_connections_total');
            $this->metrics->gauge('eventbus_active_connections', count($this->getConnections()));

            $callback($connectionId, $transport);
        });
    }

    public function onDisconnect(callable $callback): void {
        parent::onDisconnect(function($connectionId) use ($callback) {
            $this->metrics->increment('eventbus_disconnections_total');
            $this->metrics->gauge('eventbus_active_connections', count($this->getConnections()));

            $callback($connectionId);
        });
    }

    public function getMetrics(): array {
        return [
            'active_connections' => count($this->getConnections()),
            'total_messages_published' => $this->metrics->getCounter('eventbus_messages_published_total'),
            'publish_errors' => $this->metrics->getCounter('eventbus_publish_errors_total'),
            'connections_total' => $this->metrics->getCounter('eventbus_connections_total'),
            'uptime' => time() - $this->startTime
        ];
    }
}

// Usage
$eventBus = new MonitoredEventBus([
    'host' => '0.0.0.0',
    'port' => 8080
]);

// Metrics endpoint
$app->get('/eventbus/metrics', function($req, $res) use ($eventBus) {
    $metrics = $eventBus->getMetrics();
    $res->json($metrics);
});
```

## Best Practices

### Event Design
1. **Use descriptive channel names**: `user_login`, `order_created`, `payment_processed`
2. **Include context in event data**: User ID, timestamps, correlation IDs
3. **Keep events immutable**: Don't modify event data after publishing
4. **Version your events**: Handle event schema evolution

### Connection Management
1. **Implement connection limits**: Prevent resource exhaustion
2. **Use heartbeats**: Detect and clean up dead connections
3. **Handle reconnections gracefully**: Implement exponential backoff
4. **Monitor connection health**: Track connection lifecycle events

### Performance Optimization
1. **Batch messages when possible**: Reduce network overhead
2. **Use appropriate transport**: WebSocket for browsers, TCP for servers
3. **Implement message filtering**: Reduce unnecessary message processing
4. **Scale horizontally**: Distribute load across multiple instances

### Security Considerations
1. **Authenticate connections**: Verify client identity
2. **Authorize channel access**: Control who can publish/subscribe
3. **Encrypt message data**: Protect sensitive information
4. **Rate limit connections**: Prevent abuse and DoS attacks

This comprehensive documentation covers all aspects of the KislayPHP EventBus extension, from basic pub/sub messaging to advanced clustering and real-time application patterns.