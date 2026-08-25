// SPDX-License-Identifier: MIT

#pragma once

#include "handshake_base.hpp"

#include <securepath/network/encryption/context.hpp>

namespace securepath::network {

void enable_client_ss_handshake(context&);
void enable_server_ss_handshake(context&);
handshake_base_ptr construct_client_ss_handshake(context&, handshake_data const& data);
handshake_base_ptr construct_server_ss_handshake(context&, handshake_data const& data);

}
