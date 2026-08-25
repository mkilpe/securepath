// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/network/net_error.hpp>
#include <securepath/util/error.hpp>

#include <string>
#include <system_error>

namespace securepath::packet_transport::protocol {
inline namespace v1 {

enum class errc {
	no_error = 0,
	invalid_client_key,
	bad_version,
	invalid_state,
	end_of_list
};

}

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);
std::error_category const& error_category();

/// convert net_error to error using the errc from this protocol
error to_error(network::net_error const& err);

/// human readable form of a net_error for logging
std::string describe(network::net_error const& err);

}

namespace std {

	template<>
	struct is_error_condition_enum<securepath::packet_transport::protocol::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::packet_transport::protocol::errc>
		: public true_type {};
}
