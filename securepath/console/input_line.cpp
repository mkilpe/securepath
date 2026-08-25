// SPDX-License-Identifier: MIT

#include "input_line.hpp"
#include "curses.hpp"

#include <securepath/log/log.hpp>

namespace securepath::console {

input_line::input_line(event_system::event_handler& e, point pos, std::size_t size)
: window(rect{pos, {size, 1}})
, event_handler_(e)
, handler_(size)
{
}

void input_line::set_attr(attr a) {
	attr_ = a;
}

std::wstring_view input_line::text() const {
	return handler_.string();
}

void input_line::draw() const {
	auto s = handler_.visible_string();

	scoped_attr g{native_handle(), attr_};
	werase(native_handle());
	mvwaddnwstr(native_handle(), 0, 0, s.data(), s.size());
	wmove(native_handle(), 0, handler_.cursor_position());
	wrefresh(native_handle());
}

void input_line::key_event(input in) {
	if(in.ch && *in.ch == 10) { // enter key
		event_handler_.emit<events::input>(handler_.string());
		handler_.commit();
	} else {
		handler_.process(in);
	}
}

}