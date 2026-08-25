// SPDX-License-Identifier: MIT

#include "error.hpp"

namespace securepath::crypto {
namespace {

char const* errors[] = {
	"no such root key",
	"no such key",
	"invalid certificate chain",
	"invalid certificate chain CA level",
	"invalid data",
	"invalid operation",
	"invalid public key",
	"invalid certificate",
	"signature not authentic"
};

using category_type = def_error_category<errc, errc::no_such_root_key, errc::end_of_list>;

category_type& err_cat() {
	static category_type cat("securepath crypto error", errors);
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
