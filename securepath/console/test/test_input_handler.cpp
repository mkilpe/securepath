// SPDX-License-Identifier: MIT

// input_handler is the terminal-independent editing logic behind input_line;
// everything here runs without a curses screen.

#include <securepath/console/input_handler.hpp>
#include <securepath/console/attr.hpp>
#include <securepath/console/types.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <bit>

namespace securepath::console {
namespace test {

namespace {

input key(input_key k) {
	input in;
	in.key = k;
	return in;
}

input character(wchar_t c) {
	input in;
	in.ch = c;
	return in;
}

void type_string(input_handler& h, std::wstring_view s) {
	for(wchar_t c : s) {
		h.process(character(c));
	}
}

}

TEST_CASE("input_handler typing appends and moves the cursor", "[console][input_handler]") {
	input_handler h{10};
	CHECK(h.string().empty());
	CHECK(h.cursor_position() == 0);

	auto change = h.process(character(L'a'));
	CHECK(h.string() == L"a");
	CHECK(h.cursor_position() == 1);
	CHECK(change.pos == 0);
	CHECK(change.str == L"a");
	CHECK(change.cursor_pos == 1);

	type_string(h, L"bc");
	CHECK(h.string() == L"abc");
	CHECK(h.visible_string() == L"abc");
	CHECK(h.cursor_position() == 3);
}

TEST_CASE("input_handler ignores non printable characters", "[console][input_handler]") {
	input_handler h{10};
	h.process(character(L'\n'));
	h.process(input{});
	CHECK(h.string().empty());
	CHECK(h.cursor_position() == 0);
}

TEST_CASE("input_handler scrolls when text exceeds the visible size", "[console][input_handler]") {
	input_handler h{4};
	type_string(h, L"abcdef");
	CHECK(h.string() == L"abcdef");
	// cursor stays on the last column, the window shows the tail
	CHECK(h.cursor_position() == 3);
	CHECK(h.visible_string() == L"def");
}

TEST_CASE("input_handler constructed with long text shows its tail", "[console][input_handler]") {
	input_handler h{4, L"abcdef"};
	CHECK(h.cursor_position() == 3);
	CHECK(h.visible_string() == L"def");
	CHECK(h.string() == L"abcdef");
}

TEST_CASE("input_handler backspace removes before the cursor", "[console][input_handler]") {
	input_handler h{10};
	type_string(h, L"abc");
	auto change = h.process(key(input_key::backspace));
	CHECK(h.string() == L"ab");
	CHECK(h.cursor_position() == 2);
	CHECK(change.pos == 2);
	CHECK(change.cursor_pos == 2);

	h.process(key(input_key::backspace));
	h.process(key(input_key::backspace));
	CHECK(h.string().empty());
	// nothing left: no-op
	h.process(key(input_key::backspace));
	CHECK(h.string().empty());
	CHECK(h.cursor_position() == 0);
}

TEST_CASE("input_handler arrows move the cursor and insert in the middle", "[console][input_handler]") {
	input_handler h{10};
	type_string(h, L"ac");
	h.process(key(input_key::left_arrow));
	CHECK(h.cursor_position() == 1);
	h.process(character(L'b'));
	CHECK(h.string() == L"abc");
	CHECK(h.cursor_position() == 2);
	h.process(key(input_key::right_arrow));
	CHECK(h.cursor_position() == 3);
	// at the end: no-op
	h.process(key(input_key::right_arrow));
	CHECK(h.cursor_position() == 3);
	// at the start: no-op
	h.process(key(input_key::home));
	CHECK(h.cursor_position() == 0);
	h.process(key(input_key::left_arrow));
	CHECK(h.cursor_position() == 0);
}

TEST_CASE("input_handler insert key toggles overwrite mode", "[console][input_handler]") {
	input_handler h{10};
	type_string(h, L"abc");
	h.process(key(input_key::home));
	h.process(key(input_key::insert));
	h.process(character(L'x'));
	CHECK(h.string() == L"xbc");
	h.process(key(input_key::insert));
	h.process(character(L'y'));
	CHECK(h.string() == L"xybc");
}

TEST_CASE("input_handler del removes under the cursor and home/end jump", "[console][input_handler]") {
	input_handler h{10};
	type_string(h, L"abc");
	h.process(key(input_key::home));
	h.process(key(input_key::del));
	CHECK(h.string() == L"bc");
	CHECK(h.cursor_position() == 0);
	h.process(key(input_key::end));
	CHECK(h.cursor_position() == 2);
	h.process(key(input_key::del));
	CHECK(h.string() == L"bc");
}

TEST_CASE("input_handler commit stores history and up/down browse it", "[console][input_handler]") {
	input_handler h{10};
	type_string(h, L"first");
	h.commit();
	CHECK(h.string().empty());
	type_string(h, L"second");
	h.commit();
	type_string(h, L"draft");

	h.process(key(input_key::up_arrow));
	CHECK(h.string() == L"second");
	h.process(key(input_key::up_arrow));
	CHECK(h.string() == L"first");
	// beyond the oldest entry: stays
	h.process(key(input_key::up_arrow));
	CHECK(h.string() == L"first");
	h.process(key(input_key::down_arrow));
	CHECK(h.string() == L"second");
	// past the newest entry restores the draft
	h.process(key(input_key::down_arrow));
	CHECK(h.string() == L"draft");
	// not browsing: down is a no-op
	h.process(key(input_key::down_arrow));
	CHECK(h.string() == L"draft");
}

TEST_CASE("input_handler set_string and clear", "[console][input_handler]") {
	input_handler h{4};
	auto change = h.set_string(L"abcdef");
	CHECK(change.pos == 0);
	CHECK(change.str == L"def");
	CHECK(change.cursor_pos == 3);
	h.clear();
	CHECK(h.string().empty());
	CHECK(h.cursor_position() == 0);
	CHECK(h.visible_string().empty());
}

TEST_CASE("console value types", "[console]") {
	input in;
	CHECK_FALSE(in.is_valid());
	in.key = input_key::esc;
	CHECK(in.is_valid());
	input in2;
	in2.ch = L'a';
	CHECK(in2.is_valid());

	attr a;
	CHECK(a.style == style::normal);
	CHECK_FALSE(a.colour);
	attr b{colour_index{3}, style::bold | style::underline};
	REQUIRE(b.colour);
	CHECK(b.colour->index == 3);
	CHECK((b.style & style::bold) != 0);
	CHECK((b.style & style::underline) != 0);
	CHECK((b.style & style::blink) == 0);
	// styles are bit flags; every non-normal style is a single distinct bit
	for(int s : {style::highlight, style::underline, style::blink, style::dim, style::bold}) {
		CHECK(std::has_single_bit(static_cast<unsigned>(s)));
		CHECK((s & (s - 1)) == 0);
	}
	CHECK((style::highlight | style::underline | style::blink | style::dim | style::bold) == 31);
}

}
}
