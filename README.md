# securepath

Base C++ libraries shared by Secure Path projects (rumpu, spsync, ...).

| library | what it is | depends on |
|---|---|---|
| `log` | `std::format`-style logging (`{}` placeholders) with pluggable backends | – |
| `util` | small general-purpose helpers and types | `log` |
| `serialisation` | ASN.1 DER (de)serialisation framework: free `serialise(Ar&, T&)` functions dispatched via ADL | `util` |
| `event_system` | event handler / event loop primitives, broadcast observers (asio) | `util`, asio |
| `database` | database connection abstraction with an sqlite backend | `util`, sqlite3 |
| `common` | key/value store on top of `database`, version numbers | `database` |
| `crypto` | post-quantum crypto on Botan 3: ML-DSA signatures, hybrid X25519/ML-KEM envelopes, AES-256-GCM, own certificate format, key stores — see [doc/crypto.md](doc/crypto.md) | `serialisation`, `database`, Botan ≥ 3.9 |
| `network` | TLS 1.3 transport (hybrid PQ key exchange) with ML-DSA channel-bound authentication, asio based connection/server classes — see [doc/network.md](doc/network.md) | `crypto`, `common`, asio |
| `console` | ncurses text UI widgets | `event_system`, ncursesw |
| `test_frame` | Catch2 v3 support library used by every test suite | Catch2 |

Libraries whose dependencies are missing on a tool chain are skipped with a status
message at configure time (e.g. the mingw cross-build has no sqlite/Botan yet).

Requirements: CMake >= 3.25, a C++26 compiler (GCC 14 or newer; GCC 16 is
what the libraries are developed with), asio (system or fetched automatically),
and for the full set sqlite3, Botan >= 3.9 and ncursesw development packages.

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
for existing consumers). Headers are included as
`#include <securepath/serialisation/serialiser.hpp>`. Tests are off by
default when consumed; a consumer that already provides a
`Catch2::Catch2` target has it reused instead of the bundled submodule.

## Licence

MIT, Copyright (c) 2026 Secure Path Oy — see [LICENSE](LICENSE).
Catch2 (submodule) is BSL-1.0.
