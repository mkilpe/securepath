// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <string_view>

namespace securepath::crypto::detail {

/**
 * Message framing for ML-DSA signatures: "SPSIG" || u8(len(context)) || context || message.
 * Gives per-use domain separation (Botan exposes no FIPS 204 context parameter).
 * Throws invalid_context when context is longer than 255 octets.
 */
octet_vector frame_message(std::string_view context, octet_span message);

}
