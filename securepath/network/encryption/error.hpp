// SPDX-License-Identifier: MIT

#pragma once

#include <system_error>
#include <string>

namespace securepath::network {

enum class errc {
	init_network_failed = 1,
	connection_closed,
	authentication_failure,
	invalid_record,
	no_such_handshake,
	handshake_failed,
	invalid_data,
	key_not_authentic,
	bad_version,
	already_connected,
	tls_failure,
	end_of_list
};

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);

}

namespace std {
	template<>
	struct is_error_condition_enum<securepath::network::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::network::errc>
		: public true_type {};
}
