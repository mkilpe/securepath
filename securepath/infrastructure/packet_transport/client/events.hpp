// SPDX-License-Identifier: MIT

#pragma once

#include "in_packets.hpp"
#include "types.hpp"

namespace securepath::packet_transport::events {

struct on_connect {
	typedef void type();
};

struct on_disconnect {
	typedef void type(error);
};

struct on_packet {
	typedef void type(in_packet_handle);
};

struct on_error {
	typedef void type(packet_dir, packet_key_type, error);
};

}
