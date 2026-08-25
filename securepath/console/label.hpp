// SPDX-License-Identifier: MIT

#pragma once

#include "attr.hpp"
#include "window.hpp"

namespace securepath::console {

class label : public window {
public:
	label(point pos, std::size_t size, std::wstring text = {});

	void set_text(std::wstring text);
	void set_attr(attr);

	virtual void draw() const;
private:
	std::wstring text_;
	attr attr_;
};

}