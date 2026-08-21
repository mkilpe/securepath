// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/string_util.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace securepath::test {

TEST_CASE("string conversion ascii round-trip", "[string_util]") {
	std::string s = "Hello, World! 123";
	CHECK(to_string(to_wstring(s)) == s);
	CHECK(to_wstring(s).size() == s.size());
}

TEST_CASE("string conversion utf8 round-trip", "[string_util]") {
	// two-byte (umlauts), three-byte (euro), four-byte (emoji) sequences
	std::string s = "K\xC3\xA4\xC3\xA4rij\xC3\xA4 \xE2\x82\xAC \xF0\x9F\x8E\xB5";
	CHECK(to_string(to_wstring(s)) == s);
}

TEST_CASE("string conversion code points", "[string_util]") {
	std::wstring w = to_wstring("\xC3\xA4"); // U+00E4
	if constexpr(sizeof(wchar_t) == 2) {
		CHECK(w == L"ä");
	} else {
		CHECK(w.size() == 1);
		CHECK(static_cast<char32_t>(w[0]) == 0xE4);
	}

	// U+1F3B5 needs a surrogate pair on 16-bit wchar_t
	std::wstring note = to_wstring("\xF0\x9F\x8E\xB5");
	CHECK(note.size() == (sizeof(wchar_t) == 2 ? 2u : 1u));
}

TEST_CASE("string conversion invalid utf8 becomes replacement char", "[string_util]") {
	// lone continuation byte, truncated two-byte sequence, overlong NUL
	for(std::string bad : {"\x80", "\xC3", "\xC0\x80"}) {
		std::wstring w = to_wstring(bad);
		CHECK(!w.empty());
		CHECK(static_cast<char32_t>(w[0]) == 0xFFFD);
	}
	// valid text around an invalid byte survives
	std::wstring w = to_wstring("a\x80z");
	CHECK(w.size() == 3);
	CHECK(w[0] == L'a');
	CHECK(w[2] == L'z');
}

TEST_CASE("to_hex with separator", "[string_util]") {
	CHECK("30" == to_hex("0"));
	CHECK("41-42" == to_hex("AB", "-"));
	CHECK("41ABC41" == to_hex("AA", "ABC"));
	CHECK("" == to_hex("", "X"));
}

TEST_CASE("split_view", "[string_util]") {
	CHECK(split_view("") == std::vector<std::string_view>{});
	CHECK(split_view("a b c") == std::vector<std::string_view>{"a", "b", "c"});
	CHECK(split_view("a b c ") == std::vector<std::string_view>{"a", "b", "c", ""});
	CHECK(split_view(" a b c") == std::vector<std::string_view>{"", "a", "b", "c"});
	CHECK(split_view("a.b.c", ".") == std::vector<std::string_view>{"a", "b", "c"});
	CHECK(split_view("a...b.c", ".") == std::vector<std::string_view>{"a", "", "", "b", "c"});
}

}
