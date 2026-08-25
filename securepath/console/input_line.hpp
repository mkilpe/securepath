// SPDX-License-Identifier: MIT

#pragma once

#include "attr.hpp"
#include "window.hpp"
#include "input_handler.hpp"

#include <securepath/event_system/event_handler.hpp>

namespace securepath::console {

namespace events {
	struct input {
		typedef void type(std::wstring input);
	};
}

class input_line : public window {
public:
	input_line(event_system::event_handler&, point pos, std::size_t size);

	void set_attr(attr);

	std::wstring_view text() const;

	virtual void draw() const;
	virtual void key_event(input);

private:
	event_system::event_handler& event_handler_;
	input_handler handler_;
	void* native_;
	attr attr_;
};

}