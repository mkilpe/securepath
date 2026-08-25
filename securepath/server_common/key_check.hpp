// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/network/encryption/context.hpp>

// Note: the remote-object based ro_server_base of the 2021 library is not ported yet;
// it returns together with remote_object when key distribution servers are reworked.

namespace securepath::server_common {

/// throws securepath::error (errc::invalid_state) if the context has no private key or certificate chain set
void check_server_key(network::context const&);

}
