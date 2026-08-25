// SPDX-License-Identifier: MIT

#pragma once

#include "hash.hpp"
#include "mac.hpp"

namespace securepath::crypto {

mac_ptr create_hmac_sha256(octet_span key);
mac_ptr create_hmac(hash_algorithm id, octet_span key);

}
