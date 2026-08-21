// SPDX-License-Identifier: MIT

#pragma once

#include <exception>
#include <iosfwd>
#include <string>
#include <system_error>
#include <type_traits>
#include <format>

namespace securepath {

class error : public std::exception {
public:
	error(std::error_code ec = {}, std::string msg = {})
	: code_(ec)
	, msg_(std::move(msg))
	, formatted_(msg_.empty() ? code_.message() : code_.message() + ": " + msg_)
	{}

	template<typename Enum, std::enable_if_t<std::is_enum_v<Enum>, int> = 0>
	explicit error(Enum value, std::string msg = {})
	: error(make_error_code(value), std::move(msg))
	{}

	error(std::exception_ptr ex);

	std::error_code code() const { return code_; }
	std::string message() const { return msg_; }

	explicit operator bool() const { return static_cast<bool>(code_); }

	char const* what() const noexcept override {
		return formatted_.c_str();
	}

private:
	std::error_code code_;
	std::string msg_;
	std::string formatted_;
};

enum class errc {
	not_an_error = 0,
	unknown_error,
	exception_occurred,
	not_implemented,
	not_supported,
	invalid_data,
	no_such_data,
	timeout,
	invalid_state,
	constraint_violation,
	invalid_argument,
	end_of_list
};

}

//need to do these before the potential use of the templates below (std::error_condition constructor)
namespace std {

	template<>
	struct is_error_condition_enum<securepath::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::errc>
		: public true_type {};

}

namespace securepath {

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);

template<typename ErrorCode, std::enable_if_t<std::is_enum_v<ErrorCode>, int> = 0>
error make_error(ErrorCode e, std::string msg = "") {
	return error(make_error_code(e), std::move(msg));
}

template<typename Enum, Enum begin = (Enum)(int(Enum::no_error)+1), Enum end = Enum::end_of_list>
class def_error_category : public std::error_category {
public:
	template<std::size_t Size>
	def_error_category(char const* name, char const* (&errors)[Size])
	: name_(name)
	, errors_(errors)
	{
	}

	virtual char const* name() const noexcept {
		return name_;
	}

	virtual std::error_condition default_error_condition(int ev) const noexcept {
		std::error_condition ret = std::error_condition(errc::unknown_error);
		if(ev >= static_cast<int>(begin) && ev < static_cast<int>(end)) {
			ret = std::error_condition(static_cast<Enum>(ev));
		}
		return ret;
	}

	virtual bool equivalent(std::error_code const& code, int condition) const noexcept {
		return *this == code.category() && code.value() == condition;
	}

 	virtual std::string message(int ev) const {
		std::string ret = "unknown error";
		if(ev >= static_cast<int>(begin) && ev < static_cast<int>(end)) {
			ret = errors_[ev-static_cast<int>(begin)];
		}
		return ret;
 	}

	std::error_condition make_error_condition(Enum e) const {
		return std::error_condition(static_cast<int>(e), *this);
	}

	std::error_code make_error_code(Enum e) const {
		return std::error_code(static_cast<int>(e), *this);
	}

private:
 	char const* const name_;
 	char const* const (&errors_)[static_cast<int>(end)-static_cast<int>(begin)];
};

}

template <>
struct std::formatter<securepath::error> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }
    auto format(securepath::error const& err, std::format_context& ctx) const {
    	if(err) {
    		return std::format_to(ctx.out(), "{}:{}: {} ({})", err.code().category().name(), err.code().value(), err.code().message(), err.message());
		}
		return std::format_to(ctx.out(), "no error");			
    }
};


