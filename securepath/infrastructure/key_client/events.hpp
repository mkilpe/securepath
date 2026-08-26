// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/error.hpp>

namespace securepath::key_client::events {

/// emitted when the client has connected to (and authenticated) the key server
struct on_connect {
	typedef void type();
};

/// emitted when the client disconnects, carrying the reason
struct on_disconnect {
	typedef void type(securepath::error);
};

}
