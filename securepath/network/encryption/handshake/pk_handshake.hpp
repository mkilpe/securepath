// SPDX-License-Identifier: MIT

#pragma once

#include "handshake_base.hpp"

#include <securepath/network/encryption/context.hpp>

namespace securepath::network {

/// Client-side options passed through handshake_data::extract().
struct pk_handshake_client_data {
	bool require_host_restriction{true};
};

void enable_client_pk_handshake(context&);
void enable_server_pk_handshake(context&);
handshake_base_ptr construct_client_pk_handshake(context&, handshake_data const& data);
handshake_base_ptr construct_server_pk_handshake(context&, handshake_data const& data);

}
