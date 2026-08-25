// SPDX-License-Identifier: MIT

#pragma once

#include <optional>

namespace securepath::console {

// bit flags, combined with | into attr::style
namespace style {
	enum type {
		normal    = 0,
		highlight = 1 << 0,
		underline = 1 << 1,
		blink     = 1 << 2,
		dim       = 1 << 3,
		bold      = 1 << 4
	};
}

enum class colour {
	black,
	red,
	green,
	yellow,
	blue,
	magenta,
	cyan,
	white
};

struct colour_index {
	explicit colour_index(int i) : index(i) {}
	int index;
};

bool make_colour_pair(colour_index, colour foreground, colour background);

struct attr {
	attr(int style = style::normal);
	attr(colour_index, int style = style::normal);

	int style{style::normal};
	std::optional<colour_index> colour;
};

class scoped_attr {
public:
	scoped_attr(attr);
	scoped_attr(void* window, attr);
	~scoped_attr();
private:
	int to_attr();
private:
	attr attr_;
	void* window_{};
};

}
