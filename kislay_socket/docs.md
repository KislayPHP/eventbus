# KislayPHP Socket/EventBus Extension - Technical Reference

## Table of Contents
1. [Architecture](#architecture)
2. [Configuration Reference](#configuration-reference)
3. [API Reference](#api-reference)
4. [Patterns and Recipes](#patterns-and-recipes)
5. [Performance Notes](#performance-notes)
6. [Troubleshooting](#troubleshooting)

---

## Architecture

### Overview

KislayPHP Socket/EventBus is a WebSocket-based real-time communication extension for PHP, built on the Socket.IO protocol. It enables bidirectional, event-driven communication between connected clients and your PHP server using WebSocket as the primary transport, with HTTP long-polling as an automatic fallback.

The extension is powered by:
- **civetweb**: Embedded HTTP/WebSocket server for handling connections
- **Socket.IO Protocol**: Industry-standard framing and messaging layer
- **Thread Pool**: Asynchronous connection handling (configurable threads)
- **Namespace Isolation**: Independent event namespaces (default "/", custom "/admin", "/chat", etc.)
- **Room Management**: Built-in pub/sub broadcast grouping

### Socket.IO Protocol

The Socket.IO protocol defines packet types for client-server communication:

| Type | ID | Purpose | Example |
|------|----|---------|----|
| **CONNECT** | 0 | Namespace subscription | `0` (connect to "/") |
| **DISCONNECT** | 1 | Namespace unsubscription | `1` (disconnect from namespace) |
| **EVENT** | 2 | Event message with data | `2["message","hello"]` |
| **ACK** | 3 | Acknowledgment response | `3` with callback ID |
| **ERROR** | 4 | Error packet | `4["auth_failed"]` |

All packets use JSON serialization for data payloads and are framed by Engine.IO (HTTP/WebSocket protocol layer).

### Client Connection Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. HTTP CONNECT (TCP handshake + HTTP GET)                      │
│    Client requests: GET / HTTP/1.1                               │
│    Server responds: 101 Switching Protocols (WebSocket)          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. ENGINE.IO HANDSHAKE (or fallback to polling)                  │
│    Server assigns: Unique session ID (e.g., "abc123")            │
│    Shared: Capabilities (max frame size, upgrades allowed)       │
│    Client stores: Session ID for reconnection                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. TRANSPORT NEGOTIATION                                         │
│    If WebSocket available: Upgrade to WS (persistent)            │
│    Else: Stay on HTTP polling (client polls for messages)        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. SOCKET.IO CONNECT (namespace subscription)                    │
│    Client sends: CONNECT packet (type 0) with auth data          │
│    Server triggers: $socket->onAuth callback                     │
│    Decision: $next(true) → allow, $next(false) → reject + close  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. READY FOR EVENTS                                              │
│    Client/Server: Exchange EVENT packets (type 2)                │
│    Optional: ACK callbacks for confirmation                      │
│    Optional: Room joins for pub/sub broadcasting                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. DISCONNECT                                                    │
│    Initiated by: Client (close), Server (timeout), or network    │
│    Event: 'disconnect' fired on both sides                       │
│    Cleanup: Session removed, rooms cleared, handlers released    │
└─────────────────────────────────────────────────────────────────┘
```

### Transport Mechanisms

#### WebSocket Transport
- **Persistent Connection**: TCP socket held open after HTTP upgrade
- **Low Latency**: Bidirectional frames with minimal overhead
- **Preferred**: Used when available and client supports
- **Fallback**: Automatically falls back to polling if WS fails

#### HTTP Long-Polling Transport
- **Client-Initiated**: Client repeatedly polls `/socket.io/?transport=polling`
- **Server Queueing**: Messages queued until next poll request
- **Compatibility**: Works in restricted network environments
- **Automatic Upgrade**: Client attempts WebSocket upgrade after polling connection

#### Negotiation Flow
1. Client connects via HTTP/WebSocket upgrade attempt
2. If WebSocket fails → Fallback to HTTP polling
3. Once polling established → Client requests WebSocket upgrade
4. Server accepts upgrade → Connection switches to WebSocket (lower latency)

### Civetweb Integration

civetweb is an embedded C HTTP server providing:
- HTTP/1.1 and HTTP/1.0 request handling
- WebSocket support (RFC 6455 compliant)
- Configurable thread pool for concurrent connections
- CORS header handling
- SSL/TLS support (if needed)

The PHP extension wraps civetweb, binding it to a configurable `host:port` and mapping incoming connections to PHP event handlers.

### Namespace Isolation

Namespaces partition the connection space:

```
Server
├── / (default namespace)
│   ├── Socket[client1]
│   │   └── Rooms: ["lobby", "user_123"]
│   ├── Socket[client2]
│   │   └── Rooms: ["lobby"]
│   └── Event Handlers: (separate per namespace)
│
├── /admin (admin namespace)
│   ├── Socket[admin_user]
│   │   └── Rooms: ["dashboard"]
│   └── Event Handlers: (separate from /)
│
└── /chat (chat namespace)
    ├── Socket[client3]
    ├── Socket[client4]
    └── Event Handlers: (separate from / and /admin)
```

**Key Points:**
- Each namespace has independent `connect`, `disconnect`, `error` events
- Event handlers registered to one namespace do NOT fire in others
- A socket cannot broadcast outside its own namespace
- Clients must explicitly connect to each namespace

---

## Configuration Reference

### Environment Variables

Configuration is managed via environment variables and runtime `setOption()` calls. Environment variables are read at server startup.

#### KISLAY_SOCKET_THREADS
- **Type**: Integer
- **Default**: `4`
- **Range**: 1-64
- **Purpose**: Thread pool size for handling concurrent connections
- **Notes**: 
  - Higher values → More concurrent connections, more memory
  - Lower values → Potentially saturated under load
  - Recommended: 4-16 for most applications
- **Example**: `KISLAY_SOCKET_THREADS=8 php server.php`

#### KISLAY_SOCKET_PING_TIMEOUT
- **Type**: Integer (milliseconds)
- **Default**: `5000`
- **Range**: 1000-60000
- **Purpose**: Time server waits for PONG response after sending PING
- **Notes**: 
  - If PONG not received → Connection considered dead → Closed
  - Prevents zombie connections (disconnected clients lingering)
- **Example**: `KISLAY_SOCKET_PING_TIMEOUT=10000 php server.php`

#### KISLAY_SOCKET_PING_INTERVAL
- **Type**: Integer (milliseconds)
- **Default**: `25000`
- **Range**: 5000-120000
- **Purpose**: Interval between PING frames sent by server
- **Notes**: 
  - Detects dead connections, keeps NAT firewall rules active
  - Lower values → More overhead, better liveness detection
  - Higher values → Less overhead, higher disconnect detection latency
- **Example**: `KISLAY_SOCKET_PING_INTERVAL=15000 php server.php`

#### KISLAY_SOCKET_MAX_PAYLOAD
- **Type**: Integer (bytes)
- **Default**: `1048576` (1 MB)
- **Range**: 65536-16777216 (64 KB - 16 MB)
- **Purpose**: Maximum size of a single Socket.IO packet payload
- **Notes**: 
  - Prevents memory exhaustion from malicious/buggy clients
  - Applies to EVENT and ACK packets
  - Larger payloads rejected with ERROR packet
- **Example**: `KISLAY_SOCKET_MAX_PAYLOAD=5242880 php server.php` (5 MB)

#### KISLAY_SOCKET_CORS_ORIGIN
- **Type**: String
- **Default**: `"*"`
- **Purpose**: CORS allowed origin header value
- **Notes**: 
  - `"*"` allows all origins (development only)
  - `"https://example.com"` allows specific origin
  - `"https://example.com,https://app.example.com"` for multiple origins
- **Example**: `KISLAY_SOCKET_CORS_ORIGIN="https://myapp.com" php server.php`

#### KISLAY_RPC_ENABLED
- **Type**: Boolean
- **Default**: `false`
- **Purpose**: Enable gRPC EventBus backend for distributed pub/sub
- **Notes**: 
  - When enabled: Events broadcast via gRPC to other server instances
  - Requires gRPC infrastructure (separate server)
  - Disabling: Events broadcast only locally (single-server mode)
- **Example**: `KISLAY_RPC_ENABLED=1 php server.php`

### Runtime Configuration (setOption)

Beyond environment variables, configure behavior via `setOption(key, value)` before calling `listen()`:

```php
$server = new Server();

// Frame size limit (bytes)
$server->setOption('max_frame_size', 65536);

// CORS headers
$server->setOption('cors_headers', 'Content-Type, Authorization');

// Idle client timeout (seconds)
$server->setOption('idle_timeout', 120);

// Allowed upgrade transports
$server->setOption('upgrade_transports', ['websocket', 'polling']);

$server->listen('0.0.0.0', 8080);
```

---

## API Reference

### Server Class

#### Constructor

```php
$server = new Kislay\Socket\Server();
// or (with alias)
$server = new KislayPHP\Socket\Server();
```

Creates a new Socket.IO server instance. Call `listen()` or `listenAsync()` to start accepting connections.

#### setOption(string $key, mixed $value): bool

Sets runtime configuration option. Must be called before `listen()`.

```php
$server = new Server();
$success = $server->setOption('max_payload', 2097152);
if (!$success) {
    echo "Failed to set option\n";
}
$server->listen('0.0.0.0', 8080);
```

**Common Options:**
- `'max_payload'` (int): Maximum payload bytes
- `'ping_interval'` (int): Milliseconds between PING frames
- `'ping_timeout'` (int): Milliseconds to wait for PONG
- `'cors_origin'` (string): CORS allowed origin

**Returns:** `true` if set successfully, `false` if invalid option/value.

#### listen(string $host, int $port): void

Start the Socket.IO server **synchronously** (blocks until `stop()` called).

```php
$server = new Server();
$server->on('connection', function ($socket) {
    echo "Client connected: {$socket->getId()}\n";
});
$server->listen('0.0.0.0', 8080);
// Blocks here until stop() is called from another thread or signal handler
```

**Parameters:**
- `$host`: IP address to bind (e.g., `'0.0.0.0'` for all interfaces, `'127.0.0.1'` for localhost)
- `$port`: TCP port (e.g., `8080`, `3000`)

**Blocks:** Yes. Call from main entry point.

#### listenAsync(string $host, int $port): void

Start the Socket.IO server **asynchronously** (non-blocking, runs in background).

```php
$server = new Server();
$server->on('connection', function ($socket) {
    echo "Client connected: {$socket->getId()}\n";
});
$server->listenAsync('0.0.0.0', 8080);
echo "Server started in background on port 8080\n";
sleep(10); // Simulate doing other work
$server->stop();
```

**Parameters:** Same as `listen()`.

**Blocks:** No. Returns immediately. Server runs in background thread.

#### stop(): void

Stop the running server and close all client connections.

```php
$server = new Server();
$server->listenAsync('0.0.0.0', 8080);
sleep(60);
$server->stop(); // Gracefully shut down
```

**Behavior:**
- Closes all client sockets
- Triggers `disconnect` events on all connected clients
- Stops accepting new connections
- Releases thread pool resources

#### wait(): void

Block until the server stops (only meaningful after `listenAsync()`).

```php
$server = new Server();
$server->listenAsync('0.0.0.0', 8080);
// ... setup signal handlers, etc ...
$server->wait(); // Block until stop() called
```

#### on(string $event, callable $handler): void

Register a global event handler for connection-level events.

```php
// Connection: new client connected
$server->on('connection', function (Socket $socket) {
    echo "Client {$socket->getId()} connected\n";
    $socket->emit('welcome', ['message' => 'Welcome to the server']);
});

// Disconnect: client closed connection
$server->on('disconnect', function (Socket $socket, $reason) {
    echo "Client {$socket->getId()} disconnected: {$reason}\n";
});

// Error: error occurred
$server->on('error', function ($error) {
    echo "Server error: {$error}\n";
});
```

**Supported Events:**
- `'connection'`: Fired when new client connects (after auth passed)
- `'disconnect'`: Fired when client disconnects
- `'error'`: Fired on server errors

**Handler Signature:**
- `connection`: `function(Socket $socket) { }`
- `disconnect`: `function(Socket $socket, string $reason) { }`
- `error`: `function(string $error) { }`

#### onAuth(callable $handler): void

Register authentication callback for Socket.IO CONNECT handshake.

```php
$server->onAuth(function ($handshake, $next) {
    // $handshake contains:
    // - $handshake['query']: URL query params (e.g., ?token=abc)
    // - $handshake['headers']: HTTP headers
    // - $handshake['auth']: Client auth option (from client connection)
    
    $token = $handshake['query']['token'] ?? null;
    
    if (validateToken($token)) {
        $next(true); // Allow connection
    } else {
        $next(false); // Reject connection
        // or: $next('reason'); // Reject with reason
    }
});

$server->on('connection', function ($socket) {
    // This only fires if onAuth allowed the connection
    echo "Authenticated client {$socket->getId()} connected\n";
});

$server->listen('0.0.0.0', 8080);
```

**Handshake Object:**
```php
[
    'query' => ['token' => 'abc123', 'userId' => 'user_1'],
    'headers' => ['host' => 'example.com', 'user-agent' => '...'],
    'auth' => ['token' => 'abc123'] // From client auth option
]
```

**Callback Signature:** `function($handshake, $next) { }`

**$next() Behavior:**
- `$next(true)`: Allow connection to proceed
- `$next(false)`: Reject, send ERROR packet, close connection
- `$next('reason')`: Reject with error reason string

#### of(string $namespace): NamespaceSocket

Get or create a namespace and return its handler object.

```php
$admin = $server->of('/admin');
$admin->on('connection', function ($socket) {
    echo "Admin user {$socket->getId()} connected to /admin\n";
});

// Broadcast to all clients in /admin namespace
$server->of('/admin')->emit('system_message', ['data' => '..']);
```

**Parameters:**
- `$namespace`: Namespace path (e.g., `'/admin'`, `'/chat'`). Default is `'/'`.

**Returns:** `NamespaceSocket` instance for that namespace.

**Key Point:** Each namespace is isolated. Handlers registered to `/admin` do not fire for connections to `/`.

#### emit(string $event, mixed $data): void

Broadcast an event to all connected clients on all namespaces.

```php
$server->emit('server_status', ['uptime' => 3600, 'status' => 'ok']);
// All connected clients receive this event
```

**Parameters:**
- `$event`: Event name (string)
- `$data`: Data to send (array, string, etc.)

**Scope:** Broadcasts to all clients, all namespaces.

#### to(string $room): Emitter

Create an Emitter to broadcast to a specific room.

```php
$server->to('broadcast_room')->emit('announcement', [
    'message' => 'All listeners will receive this'
]);
```

**Parameters:**
- `$room`: Room name (string)

**Returns:** `Emitter` object (see below).

#### in(string $room): Emitter

Alias for `to()`. Creates an Emitter for a room.

```php
$server->in('notifications')->emit('notif', ['id' => 123]);
```

---

### Socket Class

#### emit(string $event, mixed $data, ?callable $ack = null): void

Send an event to this specific client.

```php
$socket->emit('message', ['text' => 'Hello from server']);

// With acknowledgment callback
$socket->emit('request_data', ['query' => 'username'], function ($response) {
    echo "Client responded with: " . json_encode($response) . "\n";
});
```

**Parameters:**
- `$event`: Event name
- `$data`: Data to send
- `$ack`: (Optional) Callback function called when client acknowledges

**Callback Timing:**
- If `$ack` provided: Waits for client to emit back an EVENT packet with acknowledgment
- If no `$ack`: Message sent without waiting for response (fire-and-forget)

**ACK Pattern:**
1. Server: `$socket->emit('ask', ['question' => '2+2'], function($answer) { ... })`
2. Transmitted to client as Socket.IO packet (type 2, with ID)
3. Client receives event, calls `socket.emit('ask', data, callback)`
4. Client callback invokes → Socket.IO ACK packet (type 3) sent back
5. Server callback invoked with client's response data

#### on(string $event, callable $handler): void

Register an event handler for events emitted by this client.

```php
$socket->on('message', function ($data) {
    echo "Client message: {$data['text']}\n";
});

$socket->on('get_profile', function ($data, $ack) {
    // Client sent message with ack callback
    $ack(['name' => 'John', 'status' => 'online']);
});
```

**Handler Signature:**
- `function($data)`: No ack expected
- `function($data, $ack)`: Ack callback available, call `$ack($response)` to respond

**Event Naming:** Custom event names, e.g., `'message'`, `'user_joined'`, `'command'`.

#### join(string $room): void

Add this socket to a room.

```php
$socket->on('join_chat', function ($data) {
    $roomId = $data['room'];
    $socket->join($roomId);
    echo "Socket {$socket->getId()} joined room {$roomId}\n";
});
```

**Behavior:**
- Socket now receives broadcasts to `$room`
- Socket can join multiple rooms
- Room persists until `leave()` called or socket disconnects

#### leave(string $room): void

Remove this socket from a room.

```php
$socket->on('leave_chat', function ($data) {
    $roomId = $data['room'];
    $socket->leave($roomId);
    echo "Socket {$socket->getId()} left room {$roomId}\n";
});
```

**Behavior:**
- Socket stops receiving broadcasts to `$room`
- Other clients in room are unaffected

#### to(string $room): Emitter

Create an Emitter to broadcast from this socket to a specific room.

```php
$socket->on('message', function ($msg) {
    // Broadcast to everyone in the room except this socket
    $socket->to('chatroom')->emit('message', ['from' => $socket->getId(), 'text' => $msg]);
});
```

**Returns:** `Emitter` configured for this room and socket.

#### disconnect(bool $close = false): void

Disconnect this socket.

```php
$socket->on('bye', function ($data) {
    echo "Client says goodbye\n";
    $socket->disconnect(true); // Close connection
});
```

**Parameters:**
- `$close`: If `true`, immediately close the connection. If `false`, send DISCONNECT packet and wait for client.

#### getId(): string

Get the unique socket ID (Engine.IO session ID).

```php
$id = $socket->getId();
echo "Connected socket ID: {$id}\n";
// Output: "abc123def456ghi789"
```

**Returns:** Unique string identifier for this connection.

**Stability:** Stable for the connection lifetime. New socket gets new ID.

#### getHandshake(): array

Get connection handshake data.

```php
$handshake = $socket->getHandshake();
echo "Client query: " . json_encode($handshake['query']) . "\n";
echo "Client headers: " . json_encode($handshake['headers']) . "\n";
echo "Client auth: " . json_encode($handshake['auth']) . "\n";
```

**Returns:**
```php
[
    'query' => ['token' => 'abc123', ...],
    'headers' => ['host' => '...', 'user-agent' => '...', ...],
    'auth' => ['token' => '...', ...]
]
```

---

### NamespaceSocket Class

#### on(string $event, callable $handler): void

Register an event handler at namespace level (fires for all sockets in namespace).

```php
$admin = $server->of('/admin');

$admin->on('connection', function ($socket) {
    echo "Admin connected: {$socket->getId()}\n";
});

$admin->on('disconnect', function ($socket) {
    echo "Admin disconnected: {$socket->getId()}\n";
});
```

**Supported Namespace Events:**
- `'connection'`: New socket connected to this namespace
- `'disconnect'`: Socket disconnected from this namespace
- `'error'`: Error in namespace

#### emit(string $event, mixed $data): void

Broadcast to all sockets in this namespace.

```php
$server->of('/admin')->emit('alert', ['level' => 'critical', 'msg' => '...']);
// All sockets in /admin receive the alert event
```

#### to(string $room): Emitter

Create Emitter for this namespace scoped to a specific room.

```php
$server->of('/chat')->to('room_1')->emit('message', [...]);
// Only sockets in /chat namespace AND room_1 receive it
```

#### in(string $room): Emitter

Alias for `to()`.

#### getRooms(string $socketId): array

Get list of rooms a socket is in.

```php
$rooms = $admin->getRooms($socket->getId());
// Returns: ['dashboard', 'notifications', ...]
```

**Returns:** Array of room names.

#### getClients(string $room): array

Get list of all socket IDs in a room.

```php
$clients = $server->of('/chat')->getClients('lobby');
// Returns: ['id1', 'id2', 'id3', ...]
```

**Returns:** Array of socket IDs.

---

### Emitter Class

#### emit(string $event, mixed $data): void

Send an event through this Emitter (to room, all clients, or excluding socket).

```php
// Broadcast to room
$server->to('room_1')->emit('event_name', $data);

// Broadcast from socket, excluding socket itself
$socket->to('room_1')->emit('message', $data);
```

---

## Patterns and Recipes

### 1. Chat Application

```php
<?php
require 'vendor/autoload.php';
use Kislay\Socket\Server;

$server = new Server();

$server->of('/chat')->on('connection', function ($socket) {
    $userId = $socket->getHandshake()['query']['userId'] ?? 'anonymous';
    
    // Join default lobby room
    $socket->join('lobby');
    
    // Notify others
    $socket->to('lobby')->emit('user_joined', [
        'userId' => $userId,
        'socketId' => $socket->getId()
    ]);
    
    // Handle room switch
    $socket->on('switch_room', function ($data) use ($socket) {
        $oldRoom = $data['old_room'];
        $newRoom = $data['new_room'];
        
        $socket->leave($oldRoom);
        $socket->join($newRoom);
        
        $socket->to($newRoom)->emit('user_joined', [
            'socketId' => $socket->getId(),
            'from_room' => $oldRoom
        ]);
    });
    
    // Handle messages
    $socket->on('message', function ($msg) use ($socket) {
        $socket->to('lobby')->emit('message', [
            'from' => $socket->getId(),
            'text' => $msg['text'],
            'timestamp' => time()
        ]);
    });
    
    // Disconnect cleanup
    $socket->on('disconnect', function () use ($socket, $userId) {
        echo "User {$userId} disconnected\n";
    });
});

$server->listen('0.0.0.0', 3000);
```

**Client (JavaScript):**
```javascript
const socket = io('http://localhost:3000/chat', {
    query: { userId: 'user_123' }
});

socket.on('user_joined', (data) => {
    console.log('User joined:', data.userId);
});

socket.on('message', (data) => {
    console.log(`[${data.from}]: ${data.text}`);
});

function sendMessage(text) {
    socket.emit('message', { text: text });
}

function switchRoom(oldRoom, newRoom) {
    socket.emit('switch_room', { old_room: oldRoom, new_room: newRoom });
}
```

### 2. Real-Time Dashboard

```php
<?php
$server = new Server();

$server->of('/dashboard')->on('connection', function ($socket) {
    // Send initial state
    $socket->emit('state', [
        'users_online' => getUserCount(),
        'memory_usage' => memory_get_usage(),
        'cpu_load' => sys_getloadavg()
    ]);
    
    // Join monitoring room
    $socket->join('metrics');
});

// Simulate monitoring loop in separate thread
$socket_server->listenAsync('0.0.0.0', 3000);

// In another script or thread, broadcast metrics every second
while (true) {
    $metrics = [
        'timestamp' => time(),
        'memory_usage' => memory_get_usage(),
        'cpu_load' => sys_getloadavg()[0],
        'active_connections' => getActiveConnections(),
        'requests_per_sec' => getRequestRate()
    ];
    
    $server->of('/dashboard')->to('metrics')->emit('metrics_update', $metrics);
    sleep(1);
}
```

**Client:**
```javascript
const socket = io('http://localhost:3000/dashboard');

socket.on('state', (state) => {
    console.log('Initial dashboard state:', state);
    updateDashboard(state);
});

socket.on('metrics_update', (metrics) => {
    console.log('Updated metrics:', metrics);
    updateCharts(metrics);
});
```

### 3. Pub/Sub Event Bus

```php
<?php
$server = new Server();

// Subscribe to events on a topic
$server->on('connection', function ($socket) {
    $socket->on('subscribe', function ($data) use ($socket) {
        $topic = $data['topic'];
        $socket->join('topic_' . $topic);
        echo "Socket subscribed to topic: {$topic}\n";
    });
    
    $socket->on('unsubscribe', function ($data) use ($socket) {
        $topic = $data['topic'];
        $socket->leave('topic_' . $topic);
    });
});

// Publish an event to a topic
function publishToTopic($server, $topic, $event, $data) {
    $room = 'topic_' . $topic;
    $server->to($room)->emit($event, $data);
}

// Usage
$server->on('connection', function ($socket) {
    // ...
});

$server->listenAsync('0.0.0.0', 3000);

// Publish from anywhere in application
$server->of('/')->to('topic_notifications')->emit('notification', [
    'id' => 123,
    'message' => 'System event'
]);
```

### 4. Authenticated Socket with JWT

```php
<?php
use Kislay\Socket\Server;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$server = new Server();

// Configure JWT authentication
$server->onAuth(function ($handshake, $next) {
    $token = $handshake['query']['token'] ?? null;
    
    if (!$token) {
        return $next('No token provided');
    }
    
    try {
        $decoded = JWT::decode($token, new Key('your_secret_key', 'HS256'));
        
        // Attach user info to handshake for later access
        $handshake['user'] = (array)$decoded;
        
        $next(true);
    } catch (Exception $e) {
        $next('Invalid token: ' . $e->getMessage());
    }
});

$server->on('connection', function ($socket) {
    $user = $socket->getHandshake()['user'] ?? [];
    echo "Authenticated user {$user['userId']} connected\n";
    
    $socket->on('protected_action', function ($data) use ($socket) {
        $user = $socket->getHandshake()['user'] ?? [];
        
        // Verify user has permission
        if (!isset($user['admin']) || !$user['admin']) {
            $socket->emit('error', ['message' => 'Permission denied']);
            return;
        }
        
        // Process protected action
        echo "Admin action performed by {$user['userId']}\n";
    });
});

$server->listen('0.0.0.0', 3000);
```

---

## Performance Notes

### WebSocket vs HTTP Polling

| Metric | WebSocket | HTTP Polling |
|--------|-----------|--------------|
| **Latency** | ~10-50ms | ~100-1000ms |
| **Bandwidth** | ~2-10 bytes/frame | ~100+ bytes/poll |
| **CPU Usage** | Lower (persistent connection) | Higher (new TCP + HTTP overhead) |
| **Scalability** | 10k-100k+ concurrent | 1k-10k concurrent |
| **Compatibility** | Modern browsers only | All browsers |
| **NAT/Firewall** | Blocked by restrictive firewalls | Usually works through firewalls |

**Recommendation:**
- Prefer WebSocket in modern environments
- Polling as fallback for restricted networks
- Mixed deployments: use WebSocket when available, fallback to polling

### Thread Pool Sizing

The thread pool (controlled by `KISLAY_SOCKET_THREADS`) handles concurrent connections:

```
Threads = 4  → ~100-500 concurrent connections (depending on workload)
Threads = 8  → ~300-1500 concurrent connections
Threads = 16 → ~1000-5000 concurrent connections
```

**Formula:** `Estimated Connections = Threads * 100-300`

**Tuning:**
- **CPU-bound workload** (heavy computation): Lower thread count, more processing per thread
- **I/O-bound workload** (database queries): Higher thread count, block waiting for I/O
- **Monitor:** Track CPU, memory, connection queue depth

### Broadcast Fan-Out Cost

Broadcasting to many clients has costs:

```php
// Cost scales with number of clients in room
$server->to('large_room')->emit('event', $data);
// Sends message to each client individually (fan-out)
```

**Optimization Strategies:**

1. **Use Rooms Strategically**
```php
// Bad: Broadcast to all clients
$server->emit('event', $data); // O(n) where n = all clients

// Better: Broadcast to specific room
$server->to('interested_clients')->emit('event', $data); // O(m) where m = room size
```

2. **Compress Payloads**
```php
// Bad: Large JSON payload
$socket->emit('data', ['large_array' => range(1, 10000)]); // ~100KB

// Better: Send only necessary fields
$socket->emit('data', ['ids' => [1, 2, 3, 4, 5]]); // ~50 bytes
```

3. **Batch Updates**
```php
// Bad: Multiple emit() calls
for ($i = 0; $i < 1000; $i++) {
    $server->to('room')->emit('update', $data[$i]);
}

// Better: Single emit with batch
$server->to('room')->emit('batch_updates', $data);
```

4. **ACK Timeout Impact**
```php
// Waiting for ACKs blocks the socket handler thread
$socket->emit('request', $data, function ($response) {
    // Handler waits here until client responds
    processResponse($response);
});
// If client never responds → Handler thread blocked (consider timeout)
```

### Memory Considerations

- **Per-Connection Overhead**: ~10-50 KB (varies with payload size)
- **With 1000 connections**: ~10-50 MB baseline
- **Message Queue**: Each pending message ~1-10 KB
- **Room Membership**: ~100 bytes per room per client

**Estimated Memory:**
```
Total = (Connections * 50KB) + (Queued Messages * 5KB) + Overhead
      = (1000 * 50KB) + (10K messages * 5KB) + (1000 rooms * 100B)
      = 50MB + 50MB + 100KB ≈ 100MB for moderate load
```

---

## Troubleshooting

### CORS Errors: "Access-Control-Allow-Origin header missing"

**Symptom:** Browser console shows CORS error, connection fails from web page.

**Cause:** Socket.IO connection from different origin than server.

**Solution:**

```php
// Set CORS origin via environment variable
// KISLAY_SOCKET_CORS_ORIGIN="https://myapp.com" php server.php

// Or at runtime
$server->setOption('cors_origin', 'https://myapp.com');
$server->listen('0.0.0.0', 8080);
```

**Client:**
```javascript
const socket = io('http://server:8080', {
    reconnection: true,
    reconnection_delay: 1000
});
```

**For Development** (allow all origins):
```php
putenv('KISLAY_SOCKET_CORS_ORIGIN=*');
```

### Auth Rejection: "Socket connects but immediately disconnects"

**Symptom:** Connection established briefly, then closed. Browser console shows ERROR packet.

**Cause:** `onAuth()` callback called `$next(false)`.

**Debugging:**

```php
$server->onAuth(function ($handshake, $next) {
    $token = $handshake['query']['token'] ?? null;
    
    error_log('Auth attempt with token: ' . var_export($token, true));
    
    if (!$token || !validateToken($token)) {
        error_log('Auth rejected');
        return $next('Invalid token');
    }
    
    $next(true);
});
```

**Check:**
- Is client sending auth? (Check query params: `?token=abc`)
- Is validation logic correct?
- Are environment variables/config correct?

**Client:**
```javascript
const socket = io('http://localhost:3000', {
    query: {
        token: 'your_token_here'
    },
    auth: {
        token: 'your_token_here'
    }
});

socket.on('error', (error) => {
    console.error('Connection error:', error);
});
```

### Rooms Not Broadcasting: "emit('event') works but to().emit() doesn't"

**Symptom:** Direct `$socket->emit()` works, but room broadcasts with `$server->to(room)->emit()` fail.

**Cause:** 
1. Sockets not actually in the room
2. Room name mismatch
3. Wrong namespace

**Debugging:**

```php
$socket->on('test_room', function ($data) use ($socket, $server) {
    $room = $data['room'];
    
    // Join
    $socket->join($room);
    
    // Verify
    $rooms = $server->getRooms($socket->getId());
    error_log('Rooms after join: ' . json_encode($rooms));
    
    // Get clients in room
    $clients = $server->getClients($room);
    error_log('Clients in room: ' . json_encode($clients));
    
    // Broadcast
    $server->to($room)->emit('test_event', ['msg' => 'test']);
});
```

**Check:**
- Socket actually joined? (`socket->join()` called)
- Room name correct and consistent?
- Broadcasting to correct namespace?

### Client Not Connecting: "WebSocket fails, doesn't fall back to polling"

**Symptom:** Connection timeout, no error message, client never connects.

**Cause:** 
1. Server not running
2. Firewall blocking port
3. WebSocket upgraded but polling not configured

**Debugging:**

```php
// Server side
$server->on('connection', function ($socket) {
    echo "Client connected: {$socket->getId()}\n";
});

$server->on('error', function ($error) {
    error_log('Server error: ' . $error);
});

// Enable verbose logging
error_reporting(E_ALL);
ini_set('display_errors', 1);

$server->listen('0.0.0.0', 8080);
```

**Client:**
```javascript
const socket = io('http://localhost:8080', {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnection_delay: 500,
    reconnection_delay_max: 5000,
    reconnection_attempts: 10
});

socket.on('connect', () => {
    console.log('Connected! Transport:', socket.io.engine.transport.name);
});

socket.on('connect_error', (error) => {
    console.error('Connection error:', error);
});

socket.on('error', (error) => {
    console.error('Socket error:', error);
});
```

**Check:**
- Is server listening? (`netstat -an | grep 8080`)
- Is firewall allowing port? (`telnet localhost 8080`)
- Are transports configured? (WebSocket + polling both enabled)

### High Memory Usage: "Memory grows over time, doesn't shrink"

**Symptom:** Process memory usage increases continuously.

**Cause:** 
1. Message queue not draining
2. Room membership leaking
3. Unhandled connections accumulating

**Debugging:**

```php
// Monitor connection/room count
$server->on('connection', function ($socket) {
    static $count = 0;
    $count++;
    echo "Connection #{$count}: {$socket->getId()}\n";
});

$server->on('disconnect', function ($socket) {
    static $disconnects = 0;
    $disconnects++;
    echo "Disconnect #{$disconnects}: {$socket->getId()}\n";
});

// Periodic health check
if (extension_loaded('pcntl')) {
    pcntl_signal(SIGTERM, function () use ($server) {
        $server->stop();
    });
}

$server->listen('0.0.0.0', 8080);
```

**Check:**
- Are disconnects being triggered? (Compare connection/disconnect counts)
- Are sockets leaving rooms on disconnect? (Check `getRooms()`)
- Are message queues getting backed up? (Monitor via logs)

### Slow Broadcasts: "to().emit() is slow with many clients"

**Symptom:** Broadcasting to large rooms takes seconds.

**Cause:** 
1. Payload too large (serialization overhead)
2. Too many clients in single room
3. Thread pool saturated

**Optimization:**

```php
// Before: Large payload
$server->to('users')->emit('status', [
    'status' => 'ok',
    'full_data' => $largeArray, // 1MB+
]); // Slow

// After: Minimal payload
$server->to('users')->emit('status_id', ['id' => 123]); // Fast
// Clients fetch full data separately if needed

// Split into batches
function broadcastInBatches($server, $room, $event, $clients, $chunkSize = 100) {
    foreach (array_chunk($clients, $chunkSize) as $chunk) {
        foreach ($chunk as $clientId) {
            $server->to($room)->to($clientId)->emit($event, []);
        }
        usleep(10000); // Throttle
    }
}
```

**Tuning:**
- Increase thread pool: `KISLAY_SOCKET_THREADS=16`
- Split rooms: instead of 1 large room with 10k clients, use 10 rooms with 1k clients each
- Compress payloads: send only IDs, let clients fetch details

---

## Additional Resources

- **Socket.IO Documentation**: https://socket.io/docs/
- **Engine.IO Protocol**: https://github.com/socketio/engine.io-protocol
- **civetweb GitHub**: https://github.com/civetweb/civetweb

---

*Last Updated: 2024*
*KislayPHP Socket/EventBus Extension Technical Reference*
