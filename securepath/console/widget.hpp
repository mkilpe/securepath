// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

namespace securepath::console {

class widget {
public:
	widget(rect g);
	virtual ~widget() {}

	virtual rect geometry() const;

	virtual void draw() const = 0;
	virtual void key_event(input) {}
protected:
	rect geo_;
};

}