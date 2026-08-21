// SPDX-License-Identifier: MIT

#pragma once

#include <utility>

namespace securepath {

template<typename Func>
class scope_exit {
public:
	scope_exit(Func f)
	: func_(std::move(f))
	{}

	~scope_exit() {
		try {
			func_();
		} catch(...) {
		}
	}

	scope_exit(scope_exit const&) = delete;
	scope_exit(scope_exit&&) = delete;
	scope_exit& operator=(scope_exit const&) = delete;
private:
	Func func_;
};

}

