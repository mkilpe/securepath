// SPDX-License-Identifier: MIT

#include "label.hpp"
#include "curses.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/string_util.hpp>

#include <cassert>

namespace securepath::console {

label::label(point pos, std::size_t size, std::wstring text)
: window(rect{pos, {size, 1}})
, text_(std::move(text))
{
	leaveok(native_handle(), TRUE);
}

void label::set_text(std::wstring text) {
	text_ = std::move(text);
	LOG_TRACE("text = {}, x = {}", to_string(text_), geo_.size.x);
}

void label::set_attr(attr a) {
	attr_ = std::move(a);
}

void label::draw() const {
	LOG_TRACE("label::draw");
	scoped_attr g{native_handle(), attr_};
	mvwaddnwstr(native_handle(), 0, 0, text_.c_str(), geo_.size.x);
	wrefresh(native_handle());
}

}