// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/error.hpp>

#include <cstdint>
#include <string>
#include <system_error>

namespace securepath::crypto {

inline namespace v1 {
enum class errc {
	no_such_root_key = 1,
	no_such_key,
	invalid_certificate_chain,
	invalid_certificate_chain_ca_level,
	invalid_data,
	invalid_operation,
	invalid_public_key,
	invalid_certificate,
	signature_not_authentic,
	end_of_list
};
}

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);

}

namespace std {
	template<>
	struct is_error_condition_enum<securepath::crypto::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::crypto::errc>
		: public true_type {};
}
