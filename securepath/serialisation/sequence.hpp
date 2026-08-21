// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <utility>

namespace securepath::serialisation {

template<typename Ser>
class sequence {
public:
	sequence(Ser& ser)
	: ser_(ser)
	{
		ser_.start_sequence();
	}
	sequence(Ser& ser, std::uint64_t tag)
	: ser_(ser)
	{
		ser_.start_sequence(tag_info{std::nullopt, tag});
	}
	~sequence() {
		ser_.end_sequence();
	}

	template<typename T>
	sequence& operator&(T&& v) {
		ser_ & std::forward<T>(v);
		return *this;
	}

private:
	Ser& ser_;
};

}

