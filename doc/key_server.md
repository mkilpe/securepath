# key server / key client

A small key-distribution service: clients register public keys and look up keys and
certificates over an encrypted connection. The three operations are a hand-rolled
request/response protocol over the `network` library — the same pattern as the
packet_transport client/server. Targets: libraries `key_server` and `key_client`
(matching the namespaces) plus the `key_serverd` executable; the protocol header is
shared and target-less.

## Transport

`network::encrypted_connection` / `encrypted_server` over the **public-key handshake with
the client anonymous**: the server presents its certificate chain and the client verifies
it before disclosing anything, while the client sends no credentials of its own
(`context.set_authenticate_remote(false)` on the server). Each `send()` is one message and
arrives as exactly one `on_received()`, so framing is already handled
(see [network.md](network.md)).

## Protocol (`key_server/protocol/protocol.hpp`, header-only)

DER `choice` over a typelist. Pure structs + typelist, so it needs no library target of
its own; both `key_client` and `key_server` just include it.

```
register_key_request     { u32 id; crypto::public_key key; }
find_key_request         { u32 id; crypto::public_key_id kid; }
find_certificate_request { u32 id; crypto::certificate_id cid; }
register_key_response    { u32 id; network::net_error error; }
find_key_response        { u32 id; std::optional<crypto::public_key> key; network::net_error error; }
find_certificate_response { u32 id; std::optional<crypto::certificate> cert; network::net_error error; }

using types = typelist<type_tag<register_key_request,1>, type_tag<find_key_request,2>,
  type_tag<find_certificate_request,3>, type_tag<register_key_response,4>,
  type_tag<find_key_response,5>, type_tag<find_certificate_response,6>>;
```

The `id` correlates a response to its request, so multiple calls can be outstanding at
once.

## Server (`key_server/server_lib/`, library `key_server`, executable `key_serverd`)

- `server_params : network::encrypted_net_base_params` — `port` (default
  `default_key_server_port`), an optional `endpoint` that overrides the port when set
  (`create_endpoint()` resolves the two), handshake `timeout` (10 s default).
- `server : network::encrypted_net_base` — constructed from `server_params` alone
  (sqlite-backed crypto stores from the params) or with a caller-supplied
  `network::context`. `run(net_threads, work_threads)` / `run()` /
  `run_and_wait(...)` / `close()` come from the base; `local_endpoint()` reports the
  bound endpoint (with the real port when started on port 0). Subclassable — spsync's
  server derives from it.
- `key_store` — the operations against `crypto::public_key_access` /
  `certificate_access`: `register_key` (the key must be self-authentic via `verify_me()`,
  duplicates are rejected), `find_key`, `find_certificate`.
- `key_server_connection : network::encrypted_connection` — `on_received` deserialises a
  request, runs the `key_store` operation and sends the matching response. Errors travel
  as `net_error` inside the response, never as an exception across the wire.

## Client (`key_client/`, library `key_client`)

- `client` (`key_client.hpp`) — owns the connection and a `broadcast_event_handler`;
  requires a `network::context` (the default constructor throws). `connect(host, port,
  timeout)`, `close()`, `wait_for_connection()`, `event_handler()`.
- Blocking calls `register_key(public_key)`, `find_key(public_key_id) ->
  optional<public_key>`, `find_certificate(certificate_id) -> optional<certificate>`.
- Asynchronous variants `async_register_key` / `async_find_key` /
  `async_find_certificate` return an awaitable `securepath::future<T>`
  (`securepath/util/future.hpp`): `co_await` it in a coroutine or block with `get()`.
  The awaiting coroutine resumes on the connection's io thread — hop off it with
  `resume_on(executor, ...)` when needed (see the Coroutines section of the README).
  Requests are sent immediately, so several can be pipelined before awaiting.
- Each `async_*` call allocates an `id`, stores the promise in a map and sends the
  request; `on_received` matches the response `id` and completes the promise (value or
  `net_error` as an exception). On disconnect every pending call fails.
- `events.hpp`: `on_connect { void type(); }` and `on_disconnect { void type(error); }`,
  emitted through `event_handler()`.

Only this unknown-user service exists; there is no verified-user variant.
