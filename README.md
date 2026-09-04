# securepath

Base C++ libraries shared by Secure Path projects (rumpu, spsync, ...).

| library | what it is | depends on |
|---|---|---|
| `log` | `std::format`-style logging (`{}` placeholders) with pluggable backends | – |
| `util` | small general-purpose helpers and types; coroutine primitives (`task`, `future`/`promise`, `sync_wait`, `resume_on`) | `log` |
| `serialisation` | ASN.1 DER (de)serialisation framework: free `serialise(Ar&, T&)` functions dispatched via ADL | `util` |
| `event_system` | event handler / event loop primitives, broadcast observers (asio) | `util`, asio |
| `database` | database connection abstraction with an sqlite backend | `util`, sqlite3 |
| `common` | key/value store on top of `database`, version numbers | `database` |
| `crypto` | post-quantum crypto on Botan 3: ML-DSA signatures, hybrid X25519/ML-KEM envelopes, AES-256-GCM, own certificate format, key stores — see [doc/crypto.md](doc/crypto.md) | `serialisation`, `database`, Botan ≥ 3.9 |
| `network` | TLS 1.3 transport (hybrid PQ key exchange) with ML-DSA channel-bound authentication, asio based connection/server classes — see [doc/network.md](doc/network.md) | `crypto`, `common`, asio |
| `infrastructure/packet_transport` | peer-to-peer packet transport via a relay server: protocol, `packet_server` daemon and database-backed client | `network`, `crypto`, `database` |
| `infrastructure/key_server`, `infrastructure/key_client` | public-key registration/lookup service (`key_serverd` daemon) and its client with blocking and coroutine APIs — see [doc/key_server.md](doc/key_server.md) | `network`, `crypto` |
| `console` | ncurses text UI widgets | `event_system`, ncursesw |
| `audio`, `audio_util` | audio device io with ALSA (linux) / DirectSound (windows) backends, buffers and format handling; WAV file read/write, resampling and playback helpers | `serialisation`, alsa |
| `test_frame` | Catch2 v3 support library used by every test suite | Catch2 |

Libraries whose dependencies are missing on a tool chain are skipped with a status
message at configure time (e.g. the mingw cross-build has no sqlite/Botan yet).
A [threat model](doc/threat_model.md) for the crypto and network libraries,
written as input for external security review, lives in [doc/](doc/) alongside
the design documents.

Requirements: CMake >= 3.25, a C++26 compiler (GCC 14 or newer; GCC 16 is
what the libraries are developed with; MSVC is built by the windows CI job with
`/std:c++latest`, the most MSVC offers), asio (system copy, or fetched
automatically when building standalone), and for the full set sqlite3,
Botan >= 3.9, alsa-lib and ncursesw development packages (the audio backend
needs alsa on linux; on windows it uses DirectSound).

## Building and testing

Out-of-source only, driven by `CMakePresets.json`:

```sh
git submodule update --init        # Catch2 (tests only)
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Linux builds land in `build/` (binaries in `build/bin`, archives in
`build/lib`). `cmake --preset windows` cross-compiles with the Fedora
mingw64 toolchain into `build-windows/` and runs the tests under Wine.

Options: `SECUREPATH_BUILD_TESTS` (default on when top-level),
`SECUREPATH_BUILD_TEST_FRAME` (default follows tests), `SECUREPATH_SANITIZE`.

## Using from another project

Add the repository as a git submodule or via `FetchContent`, then:

```cmake
add_subdirectory(submodules/securepath)
target_link_libraries(my_app PRIVATE securepath::serialisation)
```

Every library is exported as `securepath::<name>` (and as plain `<name>`
for existing consumers). A consuming project that provides no asio (and has
none installed) gets the asio-dependent components skipped instead of a
download: event_system builds without its asio observers, and network and
infrastructure are left out. Provide an `asio::asio` target (or system asio)
to enable them. Headers are included as
`#include <securepath/serialisation/serialiser.hpp>`. Tests are off by
default when consumed; a consumer that already provides a
`Catch2::Catch2` target has it reused instead of the bundled submodule.

## Coroutines

Asynchronous calls return an awaitable `securepath::future<T>`
(`securepath/util/future.hpp`): block with `get()` or `co_await` it in a
coroutine. `securepath/util/task.hpp` provides the `task<T>` coroutine type,
`sync_wait()` bridges back to synchronous code, and `resume_on(executor, ...)`
resumes the awaiting coroutine on an asio executor or strand instead of the
completing io thread:

```cpp
securepath::task<std::optional<crypto::public_key>>
find(key_client::client& client, asio::any_io_executor ex, crypto::public_key_id id) {
	co_return co_await securepath::resume_on(ex, client.async_find_key(id));
}
```

## Licence

MIT, Copyright (c) 2026 Secure Path Oy — see [LICENSE](LICENSE).
Catch2 (submodule) is BSL-1.0.
