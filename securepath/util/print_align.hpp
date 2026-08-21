// SPDX-License-Identifier: MIT

#pragma once

#include <sstream>

namespace securepath {

struct print_align {
	print_align(std::ostream& out, std::size_t s = 0)
	: out_(out)
	{
		if(s) {
			align(s);
		}
	}

	~print_align () {
		out_ << temp_out_.str();
	}

	template<typename T>
	print_align& operator<<(T const& v) {
		temp_out_ << v;
		return *this;
	}

	print_align& align(std::size_t s) {
		std::string str = temp_out_.str().substr(0, s);
		out_ << str << std::string(s-str.size(), ' ');
		temp_out_.clear();
		temp_out_.str("");
		return *this;
	}

	std::ostringstream temp_out_;
	std::ostream& out_;
};

}

