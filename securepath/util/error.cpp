// SPDX-License-Identifier: MIT

#include "error.hpp"

#include <iostream>

namespace securepath {

error::error(std::exception_ptr ex)
: error(make_error_code(errc::exception_occurred), [&] {
		std::string msg;
		try {
			std::rethrow_exception(ex);
		} catch(std::exception const& e) {
			msg = e.what();
		} catch(...) {
		}
		return msg;
	}())
{
}

namespace {
	char const* errors[] =
		{ "no error"
		, "unknown error"
		, "exception occurred"
		, "not implemented"
		, "not supported"
		, "invalid data"
		, "no such data exists"
		, "operation timed out"
		, "invalid state"
		, "constraint violation"
		, "invalid argument" };

	using category_type = def_error_category<errc, errc::not_an_error, errc::end_of_list>;

	category_type& err_cat() {
		static category_type cat("securepath error", errors);
		return cat;
	}
}

std::error_condition make_error_condition(errc e) {
	return err_cat().make_error_condition(e);
}

std::error_code make_error_code(errc e) {
	return err_cat().make_error_code(e);
}

}
