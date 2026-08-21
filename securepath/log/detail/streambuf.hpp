// SPDX-License-Identifier: MIT

#pragma once

#include <cassert>
#include <optional>
#include <streambuf>
#include <vector>

namespace securepath::log {

class ologstreambuf	: public std::streambuf
{
public:
	template<std::size_t Size>
	ologstreambuf(char (&static_buf)[Size], std::size_t start_pos)
	: static_buffer_(static_buf)
	{
		assert(start_pos <= Size);
		setp(static_buf, static_buf+Size);
		pbump(start_pos);
	}

	char const* begin() const {
		return pbase();
	}

	char const* end() const {
		return pptr();
	}

	std::size_t size() const {
		return static_cast<std::size_t>(end() - begin());
	}

private:
	int_type overflow(int_type c) {
		if(c != traits_type::eof()) {
			std::size_t pos = 0;
			if(!dyn_buffer_) {
				dyn_buffer_.emplace(pbase(), pptr());
				pos = pptr()-pbase();
			} else {
				pos = dyn_buffer_->size();
			}
			dyn_buffer_->resize(pos*2);
			setp(dyn_buffer_->data(), dyn_buffer_->data()+dyn_buffer_->size());
			pbump(pos);
			*pptr() = c;
			pbump(1);
		}
		return c;
	}

private:
	char* static_buffer_;
	std::optional<std::vector<char>> dyn_buffer_;
};

}

