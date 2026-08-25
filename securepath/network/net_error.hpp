// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/error.hpp>
#include <securepath/util/types.hpp>

#include <iosfwd>
#include <string>
#include <system_error>

namespace securepath::network {

/// best effort to transfer error object over the network
class net_error {
public:

	net_error() = default;

	net_error(securepath::error const& err)
	: net_error(err.code().default_error_condition(), err.message())
	{}

	net_error(std::error_condition const& err, std::string msg)
	: code_(err.value())
	, message_(err.message())
	, category_(err.category().name())
	, aux_message_(std::move(msg))
	{}

	explicit operator bool() const { return static_cast<bool>(code_); }

	int code() const { return code_; }
	std::string category() const { return category_; }
	std::string message() const { return message_; }
	std::string aux_message() const { return aux_message_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & code_ & message_ & category_ & aux_message_;
	}
private:
	int code_{};
	std::string message_;
	std::string category_;
	std::string aux_message_;
};

std::ostream& operator<<(std::ostream& out, net_error const& err);

}
