// SPDX-License-Identifier: MIT

#pragma once

#include <botan/rng.h>

namespace securepath::crypto::detail {

/// process wide, thread safe random number generator (the operating system's)
Botan::RandomNumberGenerator& rng();

}
