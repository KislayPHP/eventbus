# EventBus Class Reference

Runtime classes exported by `kislayphp/eventbus`.

## Namespace

- Primary: `Kislay\\EventBus`
- Legacy alias: `KislayPHP\\EventBus`

## `Kislay\\EventBus\\Server`

Realtime server object for publish/emit semantics and connection event handling.

### Constructor

- `__construct()`
  - Create server instance.

### Listener and Handlers

- `listen(string $host, int $port, string $path)`
  - Start realtime/event socket server listener.
- `on(string $event, callable $handler)`
  - Register event callback.

### Event Dispatch

- `send(string $event, mixed $data)`
  - Send event payload.
- `publish(string $event, mixed $data)`
  - Publish event to subscribers.
- `emit(string $event, mixed $data)`
  - Emit event to connected clients.
- `emitTo(string $room, string $event, mixed $data)`
  - Emit to specific room/channel.

## `Kislay\\EventBus\\Socket`

Per-connection socket object passed to handlers.

### Connection and Room Operations

- `id()`
  - Return socket/client identifier.
- `join(string $room)`
  - Join room.
- `leave(string $room)`
  - Leave room.

### Event Operations

- `send(string $event, mixed $data)`
  - Send event to this socket.
- `reply(string $event, mixed $data)`
  - Send reply event.
- `publish(string $event, mixed $data)`
  - Publish event through server context.
- `emit(string $event, mixed $data)`
  - Emit event.
- `emitTo(string $room, string $event, mixed $data)`
  - Emit event to a room.
