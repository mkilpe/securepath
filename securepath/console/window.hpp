// SPDX-License-Identifier: MIT

#pragma once

#include "widget.hpp"

namespace securepath::console {

class window : public widget {
public:
	window(rect g);
	~window();

	WINDOW* native_handle() const;
protected:
	void* native_;
};

}