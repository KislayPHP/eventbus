# Service Communication Guide (EventBus)

This extension is the realtime communication layer for service events.

## Namespace

- Primary: `Kislay\EventBus\Server`
- Backward compatible aliases: `KislayPHP\EventBus\Server`, `KislayPHP\EventBus\Socket`

## Pattern

Use explicit channel names:

- `svc.request.<service>` for request messages
- `svc.reply.<service>` for responses
- `evt.<domain>.<event>` for domain events

Include `traceId` and `requestId` in every payload for correlation.

## Minimal Example

See `service_communication.php` in this repository.

## Recommended Cross-Module Setup

1. Use `kislayphp/queue` for durable async commands.
2. Use this module for low-latency realtime fan-out.
3. Keep routing/timeout config in `kislayphp/config`.
4. Track transport health with `kislayphp/metrics`.
