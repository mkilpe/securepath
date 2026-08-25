// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/infrastructure/packet_transport/protocol/types.hpp>

#include <cstdint>

namespace securepath::packet_transport {

enum packet_dir {
	in,
	out
};

using packet_key_type = std::int64_t;

}
