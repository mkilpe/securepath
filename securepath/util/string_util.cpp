// SPDX-License-Identifier: MIT

#include "string_util.hpp"

#include <string>
#include <type_traits>

namespace securepath {

// std::string holds UTF-8; std::wstring holds UTF-16 where wchar_t is 16 bits
// (Windows) and UTF-32 otherwise. Invalid input becomes U+FFFD.
namespace {

constexpr char32_t replacement_char = 0xFFFD;

bool valid_code_point(char32_t cp) {
	return cp <= 0x10FFFF && (cp < 0xD800 || cp > 0xDFFF);
}

void append_utf8(std::string& out, char32_t cp) {
	if(!valid_code_point(cp)) {
		cp = replacement_char;
	}
	if(cp < 0x80) {
		out.push_back(static_cast<char>(cp));
	} else if(cp < 0x800) {
		out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
		out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
	} else if(cp < 0x10000) {
		out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
		out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
		out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
	} else {
		out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
		out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
		out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
		out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
	}
}

// decodes the code point starting at str[i] and advances i; malformed input
// (bad lead byte, truncation, bad continuation, overlong, out of range)
// consumes one byte and yields the replacement character
char32_t decode_utf8(std::string_view str, std::size_t& i) {
	unsigned char const c = str[i];
	std::size_t const len = c < 0x80 ? 1 : c < 0xC2 ? 0 : c < 0xE0 ? 2 : c < 0xF0 ? 3 : c < 0xF5 ? 4 : 0;
	constexpr char32_t min_for_len[] = {0, 0, 0x80, 0x800, 0x10000};

	if(len == 0 || i + len > str.size()) {
		++i;
		return replacement_char;
	}
	char32_t cp = len == 1 ? c : c & (0x7F >> len);
	for(std::size_t k = 1; k != len; ++k) {
		unsigned char const cc = str[i + k];
		if((cc & 0xC0) != 0x80) {
			++i;
			return replacement_char;
		}
		cp = (cp << 6) | (cc & 0x3F);
	}
	i += len;
	return valid_code_point(cp) && cp >= min_for_len[len] ? cp : replacement_char;
}

void append_wide(std::wstring& out, char32_t cp) {
	if constexpr(sizeof(wchar_t) == 2) {
		if(cp >= 0x10000) {
			cp -= 0x10000;
			out.push_back(static_cast<wchar_t>(0xD800 | (cp >> 10)));
			out.push_back(static_cast<wchar_t>(0xDC00 | (cp & 0x3FF)));
		} else {
			out.push_back(static_cast<wchar_t>(cp));
		}
	} else {
		out.push_back(static_cast<wchar_t>(cp));
	}
}

char32_t decode_wide(std::wstring_view str, std::size_t& i) {
	char32_t cp = static_cast<std::make_unsigned_t<wchar_t>>(str[i]);
	++i;
	if constexpr(sizeof(wchar_t) == 2) {
		if(cp >= 0xD800 && cp <= 0xDBFF && i < str.size()) {
			char32_t const lo = static_cast<std::make_unsigned_t<wchar_t>>(str[i]);
			if(lo >= 0xDC00 && lo <= 0xDFFF) {
				++i;
				return 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
			}
		}
	}
	return valid_code_point(cp) ? cp : replacement_char;
}

}

std::wstring to_wstring(std::string_view const& str) {
	std::wstring ret;
	ret.reserve(str.size());
	for(std::size_t i = 0; i < str.size();) {
		append_wide(ret, decode_utf8(str, i));
	}
	return ret;
}

std::string to_string(std::wstring_view const& str) {
	std::string ret;
	ret.reserve(str.size());
	for(std::size_t i = 0; i < str.size();) {
		append_utf8(ret, decode_wide(str, i));
	}
	return ret;
}

std::string to_hex(std::string const& str, std::string const& sep) {
	char const encoded[] = "0123456789ABCDEF";
	std::string ret;
	for(auto&& c : str) {
		if(!ret.empty()) {
			ret += sep;
		}
		ret += encoded[std::uint8_t(c) >> 4];
		ret += encoded[std::uint8_t(c) & 0x0f];
	}
	return ret;
}

std::vector<std::string_view> split_view(std::string_view view, std::string_view sep) {
	std::vector<std::string_view> res;
	std::string_view::size_type start = 0, end = 0;

	if(!view.empty()) {
		while(end != std::string_view::npos) {
			end = view.find_first_of(sep, start);
			if(end == std::string_view::npos) {
				res.emplace_back(view.substr(start));
			} else {
				res.emplace_back(view.substr(start, end-start));
			}
			start = end + 1;
		}
	}

	return res;
}

octet_span make_span(std::string_view v) {
	return octet_span(reinterpret_cast<std::uint8_t const*>(v.data()), v.size());
}

std::string_view make_view(octet_span s) {
	return std::string_view(reinterpret_cast<char const*>(s.data()), s.size());
}

std::vector<std::wstring_view> tokenise_view(std::wstring_view view, std::wstring_view sep) {
	std::vector<std::wstring_view> res;
	std::wstring_view::size_type start = 0, end = 0;

	if(!view.empty()) {
		while(end != std::wstring_view::npos) {
			end = view.find_first_of(sep, start);
			if(end == std::wstring_view::npos) {
				res.emplace_back(view.substr(start));
			} else if(end-start > 0) {
				res.emplace_back(view.substr(start, end-start));
			}
			start = end + 1;
		}
	}

	return res;
}

}

