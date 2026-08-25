// SPDX-License-Identifier: MIT

#pragma once

#include "public_key.hpp"

namespace securepath::crypto {

/// set the process-wide root key that anchors all certificate chains (thread-safe)
void set_root_public_key(public_key const&);
/// true when a root key has been set
bool has_root_public_key();
/// forget the root key (mainly for tests)
void clear_root_public_key();
/// get the root key used to anchor all certificate chains, throws error(errc::no_such_root_key) if none is set
public_key root_public_key();

}
