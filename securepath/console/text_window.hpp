// SPDX-License-Identifier: MIT

#pragma once

#include "window.hpp"

namespace securepath::console {

class text_window : public window {
public:
	text_window(rect g);

	void add_line(std::wstring const& line);
	void clear();

	void draw() const override;

protected:
};

}