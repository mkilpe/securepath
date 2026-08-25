// SPDX-License-Identifier: MIT

#pragma once

#include <optional>
#include <string>

// curses type, forward declared so it can be used in headers
#if defined(WIN32) or defined(USE_PDCURSES)
struct _win;
typedef _win WINDOW;
#else
struct _win_st;
typedef _win_st WINDOW;
#endif

namespace securepath::console {

struct point {
	std::size_t x, y;
};

struct rect {
	point pos;
	point size;
};

enum class input_key {
	none,
	backspace,
	esc,
	tab,
	left_arrow,
	right_arrow,
	up_arrow,
	down_arrow,
	del,
	home,
	end,
	page_up,
	page_down,
	insert,
	f1,
	f2,
	f3,
	f4,
	f5,
	f6,
	f7,
	f8,
	f9,
	f10,
	f11,
	f12,
};

struct input {
	// character if there was one
	std::optional<wchar_t> ch;
	// special input key
	input_key key{input_key::none};

	bool is_valid() const { return ch || key != input_key::none; }
};

}