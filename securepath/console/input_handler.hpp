// SPDX-License-Identifier: MIT

#pragma once

#include "widget.hpp"

#include <deque>

namespace securepath::console {

class input_handler {
public:
	using size_type = std::wstring::size_type;

	// represents visible change in the input line, str changed beginning from pos.
	struct visible_change {
		size_type pos;
		std::wstring_view str;
		size_type cursor_pos;
	};

	input_handler(size_type max_size, std::wstring text = {});

	size_type cursor_position() const;
	std::wstring_view visible_string() const;
	std::wstring_view string() const;
	visible_change set_string(std::wstring);

	visible_change process(input const&);

	/// clears input line and adds the current content to history
	void commit();

	/// clears input line
	void clear();

private:
	size_type max_size_;
	std::wstring str_;
	size_type str_pos_;
	size_type cursor_pos_;
	bool insert_mode_{true};
	std::deque<std::wstring> history_;
	std::optional<std::size_t> history_pos_;
	std::wstring temp_str_;
};

}