// SPDX-License-Identifier: MIT

#include "input_handler.hpp"

#include <securepath/log/log.hpp>

#include <cwctype>
#include <cassert>

namespace securepath::console {

input_handler::input_handler(size_type max_size, std::wstring text)
: max_size_(max_size)
, str_(std::move(text))
, str_pos_(str_.size() >= max_size_ ? str_.size() - max_size_ + 1 : str_.size())
, cursor_pos_(str_.size() >= max_size_ ? max_size_ - 1 : str_.size())
{}

input_handler::size_type input_handler::cursor_position() const {
	return cursor_pos_;
}

std::wstring_view input_handler::visible_string() const {
	size_type len = max_size_;
	if(str_.size() - str_pos_ < len) {
		len = str_.size() - str_pos_;
	}
	return {str_.data() + str_pos_, len};
}

std::wstring_view input_handler::string() const {
	return str_;
}

input_handler::visible_change input_handler::set_string(std::wstring s) {
	str_ = std::move(s);
	str_pos_ = str_.size() >= max_size_ ? str_.size() - max_size_ + 1 : 0;
	cursor_pos_ = str_.size() >= max_size_ ? max_size_ - 1 : str_.size();

	return visible_change{0, visible_string(), cursor_pos_};
}

input_handler::visible_change input_handler::process(input const& in) {
	visible_change ret{};

	if(in.ch && std::iswprint(*in.ch)) {
		//add/modify char
		if(str_pos_ + cursor_pos_ >= str_.size()) {
			str_.push_back(*in.ch);
		} else {
			if(insert_mode_) {
				str_.insert(str_pos_ + cursor_pos_, 1, *in.ch);
			} else {
				str_[str_pos_ + cursor_pos_] = *in.ch;
			}
		}
		++cursor_pos_;
		if(cursor_pos_ >= max_size_) {
			++str_pos_;
			cursor_pos_ = max_size_ - 1;
			ret = visible_change{0, visible_string(), cursor_pos_};
		} else {
			ret = visible_change{cursor_pos_-1
				, {str_.data() + str_pos_ + cursor_pos_ - 1, 1}
				, cursor_pos_};
		}
	} else if(in.key == input_key::backspace) {
		//remove char
		if(cursor_pos_ > 0) {
			--cursor_pos_;
			str_.erase(str_.begin() + str_pos_ + cursor_pos_);
			ret = visible_change{cursor_pos_
				, visible_string().substr(cursor_pos_)
				, cursor_pos_};
		} else if(str_pos_ > 0) {
			--str_pos_;
			str_.erase(str_.begin() + str_pos_);
			ret = visible_change{0
				, visible_string()
				, cursor_pos_};
		}
	} else if(in.key == input_key::left_arrow) {
		//move cursor
		if(cursor_pos_ > 0) {
			--cursor_pos_;
			ret = visible_change{0, {}, cursor_pos_};
		} else if(str_pos_ > 0) {
			--str_pos_;
			ret = visible_change{0, visible_string(), cursor_pos_};
		}
	} else if(in.key == input_key::right_arrow) {
		//move cursor
		if(str_pos_ + cursor_pos_ < str_.size()) {
			if(cursor_pos_ + 1 < max_size_) {
				++cursor_pos_;
				ret = visible_change{0, {}, cursor_pos_};
			} else if(str_pos_ + cursor_pos_ < str_.size()) {
				++str_pos_;
				ret = visible_change{0, visible_string(), cursor_pos_};
			}
		}
	} else if(in.key == input_key::up_arrow) {
		if(history_pos_) {
			if(*history_pos_ > 0) {
				--*history_pos_;
				ret = set_string(history_[*history_pos_]);
			}
		} else {
			if(!history_.empty()) {
				temp_str_ = str_;
				history_pos_ = history_.size()-1;
				ret = set_string(history_[*history_pos_]);
			}
		}
	} else if(in.key == input_key::down_arrow) {
		if(history_pos_) {
			++*history_pos_;
			if(*history_pos_ >= history_.size()) {
				history_pos_ = std::nullopt;
				ret = set_string(temp_str_);
				temp_str_.clear();
			} else {
				ret = set_string(history_[*history_pos_]);
			}
		}
	} else if(in.key == input_key::del) {
		if(str_pos_ + cursor_pos_ < str_.size()) {
			//t: set visible change?
			str_.erase(str_pos_ + cursor_pos_, 1);
		}
	} else if(in.key == input_key::home) {
		//t: set visible change?
		str_pos_ = 0;
		cursor_pos_ = 0;
	} else if(in.key == input_key::end) {
		//t: set visible change?
		str_pos_ = str_.size() >= max_size_ ? str_.size() - max_size_ + 1 : 0;
		cursor_pos_ = str_.size() >= max_size_ ? max_size_ - 1 : str_.size();
	} else if(in.key == input_key::insert) {
		insert_mode_ = !insert_mode_;
	}

	assert(str_pos_ + cursor_pos_ <= str_.size());

	return ret;
}

void input_handler::commit() {
	history_.push_back(str_);
	clear();
}

void input_handler::clear() {
	str_.clear();
	temp_str_.clear();
	str_pos_ = 0;
	cursor_pos_ = 0;
}

}