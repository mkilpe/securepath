// SPDX-License-Identifier: MIT

#include "text_window.hpp"
#include "curses.hpp"

namespace securepath::console {

text_window::text_window(rect g)
: window(g)
{
	idlok(native_handle(), true);
	scrollok(native_handle(), true);
}

void text_window::add_line(std::wstring const& line) {
	wprintw(native_handle(), "%S\n", line.c_str());
}

void text_window::clear() {
	werase(native_handle());
}

void text_window::draw() const {
	wrefresh(native_handle());
}

}