// SPDX-License-Identifier: MIT

#include "attr.hpp"
#include "curses.hpp"

#include <securepath/log/log.hpp>

namespace securepath::console {

static int style_to_curses(int s) {
	int ret = A_NORMAL; // == 0
	if(s & style::highlight) {
		ret |= A_STANDOUT;
	}
	if(s & style::underline) {
		ret |= A_UNDERLINE;
	}
	if(s & style::blink) {
		ret |= A_BLINK;
	}
	if(s & style::dim) {
		ret |= A_DIM;
	}
	if(s & style::bold) {
		ret |= A_BOLD;
	}
	return ret;
}

static int colour_to_curses(colour c) {
	switch(c) {
		case colour::black:   return COLOR_BLACK;
		case colour::red:     return COLOR_RED;
		case colour::green:   return COLOR_GREEN;
		case colour::yellow:  return COLOR_YELLOW;
		case colour::blue:    return COLOR_BLUE;
		case colour::magenta: return COLOR_MAGENTA;
		case colour::cyan:    return COLOR_CYAN;
		case colour::white:   return COLOR_WHITE;
	}
	return COLOR_WHITE;
}

bool make_colour_pair(colour_index i, colour foreground, colour background) {
	bool ret = i.index < COLOR_PAIRS;
	if(ret) {
		LOG_TRACE("init colour - {} {} {}", i.index, colour_to_curses(foreground), colour_to_curses(background));
		init_pair(i.index, colour_to_curses(foreground), colour_to_curses(background));
	}
	return ret;
}

attr::attr(int style)
: style(style)
{
}

attr::attr(colour_index c, int style)
: style(style)
, colour(c)
{
}

scoped_attr::scoped_attr(attr a)
: attr_(a)
{
	attron(to_attr());
}

scoped_attr::scoped_attr(void* w, attr a)
: attr_(a)
, window_(w)
{
	wattron(static_cast<WINDOW*>(window_), to_attr());
}

int scoped_attr::to_attr() {
	int s = style_to_curses(attr_.style);
	if(attr_.colour) {
		s |= COLOR_PAIR(attr_.colour->index);
	}
	return s;
}

scoped_attr::~scoped_attr() {
	if(window_) {
		wattroff(static_cast<WINDOW*>(window_), to_attr());
	} else {
		attroff(to_attr());
	}
}

}