// SPDX-License-Identifier: MIT

#pragma once

#include "public_key.hpp"

#include <string>

namespace securepath::crypto {

/// set the process-wide root key that anchors all certificate chains (thread-safe)
void set_root_public_key(public_key const&);
/// true when a root key has been set
bool has_root_public_key();
/// forget the root key (mainly for tests)
void clear_root_public_key();
/// get the root key used to anchor all certificate chains, throws error(errc::no_such_root_key) if none is set
public_key root_public_key();

/// read a DER encoded public key from a file (as written by save_public_key_file), throws on failure
public_key load_public_key_file(std::string const& path);
/// write a public key DER encoded to a file, throws on failure
void save_public_key_file(std::string const& path, public_key const&);
/// set the process-wide root key from a DER encoded public key file (deployment anchor)
void set_root_public_key_from_file(std::string const& path);

}
