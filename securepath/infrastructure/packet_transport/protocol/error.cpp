// SPDX-License-Identifier: MIT

#include "error.hpp"

#include <securepath/log/log.hpp>

#include <format>

namespace securepath::packet_transport::protocol {
namespace {
	char const* errors[] =
		{ "invalid client key"
		, "bad version"
		, "invalid state"
		};

	using category_type = def_error_category<errc>;

	category_type& err_cat() {
		static category_type cat("packet transport protocol error", errors);
		return cat;
	}

	bool is_protocol_code(int code) {
		return code > static_cast<int>(errc::no_error) && code < static_cast<int>(errc::end_of_list);
	}
}

std::error_condition make_error_condition(errc e) {
	return err_cat().make_error_condition(e);
}

std::error_code make_error_code(errc e) {
	return err_cat().make_error_code(e);
}

std::error_category const& error_category() {
	return err_cat();
}

error to_error(network::net_error const& err) {
	error ret;
	if(err) {
		// todo: better handling of error translation
		if(err.category() == protocol::error_category().name() && is_protocol_code(err.code())) {
			ret = make_error(protocol::errc(err.code()), err.aux_message());
		}
		if(!ret) {
			LOG_WARN("unknown error code from server: {}", describe(err));
			ret = make_error(securepath::errc::unknown_error);
		}
	}
	return ret;
}

std::string describe(network::net_error const& err) {
	return std::format("{}:{}: {} ({})", err.category(), err.code(), err.message(), err.aux_message());
}

}
