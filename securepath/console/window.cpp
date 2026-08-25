// SPDX-License-Identifier: MIT

#include "window.hpp"
#include "curses.hpp"

#include <stdexcept>

namespace securepath::console {

window::window(rect g)
: widget(g)
, native_(newwin(geo_.size.y, geo_.size.x, geo_.pos.y, geo_.pos.x))
{
	if(!native_) {
		throw std::runtime_error("could not create window");
	}
}

window::~window() {
	if(native_) {
		delwin(native_handle());
	}
}

WINDOW* window::native_handle() const {
	return static_cast<WINDOW*>(native_);
}

}