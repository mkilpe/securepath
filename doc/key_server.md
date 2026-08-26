# key server / key client — hand-rolled request/response (no remote_object)

Status: design 2026-08-26. Replaces the 2021 `infrastructure/{key_server,key_client_lib}`, which
were built on the generic `remote_object` RPC framework (~6.8k lines) plus `client_common`/
`server_common` bases and the (now removed) Diffie-Hellman handshake. spsync only needs a tiny key
distribution service, so instead of porting remote_object we hand-roll the same three operations as
a small request/response protocol over the modern `network` library, exactly like the ported
`packet_transport` client/server.

## What spsync uses (the whole surface)

Client (`key_client::client`):
- `client(network::context&)`, `connect(host, port, timeout)`, `close()`,
  `wait_for_connection()`, `event_handler() -> event_system::broadcast_event_handler&`
- `register_key(public_key)`, `find_key(public_key_id) -> optional<public_key>`,
  `find_certificate(certificate_id) -> optional<certificate>` (blocking)
- `async_register_key(...)`, `async_find_key(...)`, `async_find_certificate(...)` returning a
  `key_client::future<T>` with `.then(f)` and `.get()`
- connection events `key_client::events::{on_connect, on_disconnect}` (observed via
  `event_system::asio_broadcast_observer`)

Server (`key_server::server`):
- `server_params{ uint16_t port; ... }`, `default_key_server_port`
- `server(params)` (sqlite-backed) and `server(network::context&, params)`
- `init()`, `run(n, m)`, `wait()`, `close()` (from `network::net_base` / `encrypted_net_base`),
  subclassable (spsync_server derives from it)

Targets: exactly two libraries, `key_client` and `key_server` (matching the namespaces), plus a
`key_serverd` executable. The protocol header is shared and target-less.

## Transport

`network::encrypted_connection` / `encrypted_server` over the **public-key handshake with the client
anonymous**: the server presents its certificate chain and the client verifies it, while the client
sends no credentials (`context.set_authenticate_remote(false)` on the server). This is strictly
better than the old anonymous DH: the client now authenticates the key server. Each `send()` is one
message and arrives as exactly one `on_received()`, so framing is already handled.

## Protocol (`key_server/protocol/protocol.hpp`, header-only)

DER `choice` over a typelist, same mechanism as packet_transport. Pure structs + typelist, so it
needs no library target of its own; both `key_client` and `key_server` just include it.

```
struct key_request     { std::uint32_t id; };              // base fields via a shared header
register_key_request   { u32 id; crypto::public_key key; }
find_key_request       { u32 id; crypto::public_key_id kid; }
find_certificate_request { u32 id; crypto::certificate_id cid; }
register_key_response  { u32 id; network::net_error error; }
find_key_response      { u32 id; std::optional<crypto::public_key> key; network::net_error error; }
find_certificate_response { u32 id; std::optional<crypto::certificate> cert; network::net_error error; }

using types = typelist<type_tag<register_key_request,1>, type_tag<find_key_request,2>,
  type_tag<find_certificate_request,3>, type_tag<register_key_response,4>,
  type_tag<find_key_response,5>, type_tag<find_certificate_response,6>>;
```

The `id` correlates a response to its request so multiple calls can be outstanding; a client that
issues one at a time (spsync's async_key_query) still works.

## Server logic (`key_server/server_lib/`, library target `key_server`; executable `key_serverd`)

- `key_store` (was `unknown_user_ro_object`): `register_key` (verify_me + reject duplicates, then
  insert), `find_key`, `find_certificate` against `crypto::public_key_access` / `certificate_access`.
- `key_server_connection : network::encrypted_connection`: `on_received` deserialises a request,
  runs the `key_store` op, sends the matching response (errors become `net_error` in the response,
  never an exception across the wire).
- `server : network::encrypted_net_base`: builds a `network::context` (sqlite
  caches or a supplied context), `set_authenticate_remote(false)`, `enable_server_pk_handshake`,
  owns an `encrypted_server` whose `create_connection()` returns a `key_server_connection` bound to
  `keys()`/`certs()`. `init()`/`run()`/`wait()`/`close()` come from the base.

## Client (`key_client/`, library target `key_client`)

- `future<T>` (`future.hpp`): shared state with a `std::promise<T>`; `.get()` blocks, `.then(f)`
  invokes `f(std::future<T>)` on the io thread when the response arrives. ~60 lines, no deps.
- `events.hpp`: `on_connect { void type(); }`, `on_disconnect { void type(error); }`.
- `client` (file `key_client.{hpp,cpp}`): owns a `key_client_connection : encrypted_connection` and a
  `broadcast_event_handler`. `connect` uses the pk handshake with no own credentials; `on_connected`
  emits `on_connect` and releases `wait_for_connection`; `on_disconnected` emits `on_disconnect` and
  fails every pending call. Each `async_*` allocates an `id`, stores the promise in a map, sends the
  request; `on_received` matches the response `id` and completes the promise (value or `net_error`).
  Blocking `find_key` etc. are `async_*().get()`.

## spsync changes needed (phase 0.1, not done here)

- class/type names dropped the redundant `unknown_user_` prefix:
  `key_client::unknown_user_key_client` -> `key_client::client`,
  `key_server::unknown_user_key_server` -> `key_server::server`,
  `unknown_user_key_server_params` -> `server_params`,
  `default_unknown_user_key_server_port` -> `default_key_server_port`.
- include paths: `infrastructure/key_client_lib/unknown_user_key_client.hpp` ->
  `infrastructure/key_client/key_client.hpp`;
  `infrastructure/key_server/server_lib/unknown_user_key_server.hpp` ->
  `.../server_lib/key_server.hpp`; `defaults.hpp` path unchanged.
- events: `ro::events::on_connect/on_disconnect` -> `key_client::events::on_connect/on_disconnect`;
  drop the `#include <securepath/remote_object/...>` lines in `async_key_query.{hpp,cpp}`.
- link `key_client` / `key_server` (were `key_client_lib` / `key_server_lib`).
- unchanged: `.then(f)` (receives `std::future<T>`), `.get()`, `connect`, blocking
  `find_key`/`register_key`, and `spsync_server`'s `init/run/wait/close`. The
`.then(f)`/`.get()`/`connect`/`find_key`/`register_key` call sites and `spsync_server`'s
`init/run/wait/close` are unchanged.

## Not ported

`verified_user_key_server` / `verified_user_ro_object` (spsync does not use them; they need the
mutual-auth remote object and return with remote_object if ever required). `remote_object`,
`client_common`, `server_common::ro_server_base` stay unported.
