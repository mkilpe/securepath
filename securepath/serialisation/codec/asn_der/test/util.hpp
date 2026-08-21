// SPDX-License-Identifier: MIT

#include <securepath/serialisation/codec/asn_der/asn_der_decoder.hpp>
#include <securepath/serialisation/codec/asn_der/asn_der_encoder.hpp>
#include <securepath/util/print_util.hpp>
#include <securepath/util/string_util.hpp>

#include <cmath>
#include <limits>
#include <functional>
#include <iostream>

namespace securepath::serialisation::test {

template<typename Type>
bool check_integer(Type v, std::optional<tag_info> tag, std::initializer_list<uint8_t> enc) {
	using promote_type = typename std::conditional<std::is_unsigned<Type>::value, std::uint64_t, std::int64_t>::type;
	bool ret = true;
	std::string encoded(enc.begin(), enc.end());
	std::stringstream str;
	asn_der_encoder<std::stringstream> encoder(str);
	encoder.encode(promote_type{v}, tag, sizeof(v));
	if(!encoded.empty()) {
		ret = str.str() == encoded;
		if(!ret) {
			std::cout << "encoded bytes do not match: " << to_hex(str.str()) << " != " << to_hex(encoded) << std::endl;
		}
	}
	asn_der_decoder<std::stringstream> decoder(str);
	promote_type n{};
	decoder.decode(n, tag, sizeof(n));
	return ret && v == Type(n);
}

template<typename Type>
bool check_integer(Type v, std::initializer_list<uint8_t> enc) {
	return check_integer(v, std::nullopt, enc);
}

template<typename Type, typename Compare = std::equal_to<>>
bool check(Type v, std::optional<tag_info> tag, std::initializer_list<uint8_t> enc = {}, Compare comp = {}) {
	bool ret = true;
	std::string encoded(enc.begin(), enc.end());
	std::stringstream str;
	asn_der_encoder<std::stringstream> encoder(str);
	encoder.encode(v, tag);
	if(!encoded.empty()) {
		ret = str.str() == encoded;
		if(!ret) {
			std::cout << "encoded bytes do not match: " << to_hex(str.str()) << " != " << to_hex(encoded) << std::endl;
		}
	}
	asn_der_decoder<std::stringstream> decoder(str);
	Type n{};
	decoder.decode(n, tag);
	return ret && comp(v,n);
}

template<typename Type, typename Compare = std::equal_to<>>
bool check(Type v, std::initializer_list<uint8_t> enc = {}, Compare comp = {}) {
	return check(v, std::nullopt, enc, comp);
}

template<typename Type>
bool check_real(Type value, std::initializer_list<uint8_t> enc = {}) {
	return check(value, enc, [](auto x, auto y)
		{
			if(std::isfinite(x) && std::isfinite(y)) {
				return std::fabs(x-y) <= std::numeric_limits<Type>::epsilon() * std::fabs(x+y)
					|| std::fabs(x-y) < std::numeric_limits<Type>::min();
			} else if(std::isnan(x) && std::isnan(y)) {
				return true;
			} else if(!std::isnan(x) && !std::isnan(y)) {
				return x == y;
			} else {
				return false;
			}
		});
}

}
