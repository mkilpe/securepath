// SPDX-License-Identifier: MIT

#include "error.hpp"

#include <securepath/util/error.hpp>

namespace securepath::network {

namespace {
	char const* errors[] =
		{	"Initialising network failed",
			"Connection closed",
			"Authentication failed",
			"Invalid record",
			"No such handshake",
			"Handshake failed",
			"Invalid data",
			"Key is not authentic",
			"bad version number",
			"already connected",
			"TLS failure" };

	using category_type = def_error_category<errc, errc::init_network_failed, errc::end_of_list>;

	category_type& err_cat() {
		static category_type cat("securepath network error", errors);
		return cat;
	}
}

std::error_condition make_error_condition(errc e) {
	return std::error_condition(static_cast<int>(e), err_cat());
}

std::error_code make_error_code(errc e) {
	return std::error_code(static_cast<int>(e), err_cat());
}

}
