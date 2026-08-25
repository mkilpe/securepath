// SPDX-License-Identifier: MIT

#pragma once

#include "private_key.hpp"
#include "suite.hpp"

namespace securepath::crypto {

/// generate a fresh identity (ML-DSA signing key + hybrid KEM key) for the suite
private_key generate_private_key(suite = default_suite());

}
