// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/serialisation/types.hpp>

#include <climits>
#include <cmath>
#include <cstring>
#include <optional>
#include <string>
#include <time.h>

namespace securepath::serialisation {

inline
asn_class_type get_asn_class(std::optional<tag_info> const& t) {
	return t
		? static_cast<asn_class_type>(t->tag_type.value_or(asn_class::context_specific_c))
		: static_cast<asn_class_type>(asn_class::universal_c);
}

inline
uint64_t get_tag(std::optional<tag_info> const& t, uint64_t default_tag) {
	return t ? t->tag : default_tag;
}

template<typename Integer>
inline
std::uint_fast8_t highest_bit_block(Integer value, bool treat_as_signed, std::uint_fast8_t size_hint = sizeof(Integer), std::uint_fast8_t block = 8) {
	int bit = size_hint*8-1;
	for(; bit >= 0 && (value & (uint64_t(1) << bit)) == 0; --bit) { }
	if(treat_as_signed && ((bit + 1) % block) == 0) { //consider the sign
		++bit;
	}
	return bit / block;
}

template<typename Integer>
inline
std::uint8_t bits_from_position(Integer value, std::uint_fast8_t pos, std::uint_fast8_t bit_mask) {
	return pos < sizeof(value)*8 ? (value >> pos) & bit_mask : 0;
}

template<typename Integer, std::size_t S>
inline
std::uint_fast8_t encode_to_octets(Integer value, std::uint8_t (&buf)[S], std::uint_fast8_t size_hint, bool treat_as_signed, std::uint_fast8_t block = 8, uint8_t mask = 0) {
	std::uint_fast8_t length = highest_bit_block(value, treat_as_signed, size_hint, block)+1;
	if( length > S ) {
		throw serialisation_error("illegal size");
	}
	std::uint_fast8_t bit_mask = (uint_fast8_t(1) << block)-1;
	for(uint_fast8_t i = 0; i != length; ++i) {
		buf[i] = bits_from_position(value, (length-i-1)*block, bit_mask) | mask;
	}
	return length;
}

template<typename Integer>
inline
Integer decode_from_octets(std::uint8_t const* b, std::size_t s) {
	Integer ret{};
	if(s) {
		ret = Integer{b[0]};
		for(std::size_t i = 1; i != s; ++i) {
			ret = (ret << 8) | b[i];
		}
	}
	return ret;
}

template<typename Integer>
inline
std::uint64_t translate_negative(Integer value, std::uint_fast8_t size_hint) {
	std::uint64_t number = -(value + 1);
	std::uint_fast8_t octets = highest_bit_block(number, true, size_hint)+1;
	uint64_t mask = (((1ULL << (octets*8-1))-1)<<1) | 1;
	return number ^ mask;
}

template<typename Integer, std::size_t S>
inline
std::uint_fast8_t encode_integer(Integer value, std::uint8_t (&buf)[S], std::uint_fast8_t size_hint) {
	return value < 0
		? encode_to_octets(translate_negative(value, size_hint), buf, size_hint, false)
		: encode_to_octets(value, buf, size_hint, true);
}

template<typename Integer>
inline
Integer decode_integer(std::uint8_t const* b, std::size_t s, std::uint_fast8_t size_hint) {
	Integer ret{};
	if(b[0] & 0x80) { //signed
		std::uint64_t value = decode_from_octets<std::uint64_t>(b, s);
		std::uint_fast8_t octets = highest_bit_block(value, false, size_hint)+1;
		uint64_t mask = (((1ULL << (octets*8-1))-1)<<1) | 1;
		value ^= mask;
		ret = static_cast<Integer>(-std::int64_t(value)-1);
	} else {
		ret = decode_from_octets<Integer>(b, s);
	}
	return ret;
}

template<typename Real, std::size_t S>
inline
std::uint_fast8_t encode_special_real(Real value, std::uint8_t (&buf)[S]) {
	std::uint_fast8_t length = 1;
	if(std::isnan(value)) {
		buf[0] = 0x40 | 0x02; // bits 7 and 2
	} else if(std::isinf(value)) {
		buf[0] = 0x40 | (std::signbit(value) ? 0x01 : 0x00); // bits 7 and 1 in case of negative
	} else if(value == Real{}) {
		if(std::signbit(value)) {
			buf[0] = 0x40 | 0x02 | 0x01; //bits 7, 2 and 1
		} else {
			length = 0;
		}
	} else {
		throw serialisation_error("not a special real value");
	}
	return length;
}

template<typename Real, std::size_t S>
inline
std::uint_fast8_t export_mantissa(Real mantissa, std::uint8_t (&buf)[S]) {
	static_assert(sizeof(Real) <= S, "too small buffer");
	// shift the value by 8 to left (multiply by 256) to get uint8 values out of the real
	std::uint_fast8_t length = 0;
	for(std::uint_fast8_t i = 0; i != sizeof(Real); ++i) {
		mantissa *= 256;
		std::uint8_t value = static_cast<std::uint8_t>(mantissa);
		mantissa -= value;
		buf[i] = value;
		if(value) {
			length = i+1;
		}
	}
	return length;
}

inline
std::uint_fast8_t normalise_mantissa(std::uint8_t* buffer, std::size_t size) {
	// DER normalisation requires the mantissa to be 0 or odd, shift right until it is
	// notice that after exporting mantissa, there can't be empty trailing bytes, meaning the shift is 7 bits at maximum

	std::uint_fast8_t least_sig_bit = 0;

	// first find the least significant bit
	for(; least_sig_bit != 8 && ((1 << least_sig_bit) & buffer[size-1]) == 0; ++least_sig_bit) {}

	if(least_sig_bit) {
		// shift to right least_sig_bit amount
		for(std::uint_fast8_t i = size-1; i != 0; --i) {
			std::uint8_t new_high_bits = buffer[i-1] & ((1<<least_sig_bit)-1);
			buffer[i] = (buffer[i] >> least_sig_bit) | (new_high_bits << (8-least_sig_bit));
		}
		buffer[0] >>= least_sig_bit;
	}

	return least_sig_bit;
}

template<typename Real, std::size_t S>
inline
std::uint_fast8_t encode_normal_real(Real value, std::uint8_t (&buf)[S]) {
	static_assert(sizeof(Real) + sizeof(int) + 2 <= S, "too small buffer");

	std::uint8_t mantissa_buf[sizeof(Real)];
	int exponent = 0;
	// handle mantissa
	Real mantissa = std::abs(std::frexp(value, &exponent));
	std::uint_fast8_t man_length = export_mantissa(mantissa, mantissa_buf);
	std::uint_fast8_t least_sig_bit = normalise_mantissa(mantissa_buf, man_length);
	exponent -= man_length*8 - least_sig_bit;
	// handle exponent
	std::uint8_t exponent_buf[sizeof(int)+1];
	std::uint_fast8_t exp_length = encode_integer(exponent, exponent_buf, sizeof(int));

	std::uint_fast8_t length = 1 + man_length + exp_length;
	std::uint8_t* wpos{};
	if(exp_length > 3) {
		++length;
		buf[0] = 0x03;
		buf[1] = exp_length;
		wpos = buf+2;
	} else {
		buf[0] = exp_length-1;
		wpos = buf+1;
	}
	// sign, encoding base 2, scale factor 0
	buf[0] |= 0x80 | (std::signbit(value) ? 0x40 : 0x00);
	std::memcpy(wpos, exponent_buf, exp_length);
	std::memcpy(wpos+exp_length, mantissa_buf, man_length);
	return length;
}

template<typename Real, std::size_t S>
inline
std::uint_fast8_t encode_real(Real value, std::uint8_t (&buf)[S]) {
	return std::isnormal(value)
		? encode_normal_real(value, buf) : encode_special_real(value, buf);
}

template<typename Real>
inline
Real decode_special_real(std::uint8_t data) {
	Real value{};
	if(data == (0x40|0x02)) {
		value = std::numeric_limits<Real>::quiet_NaN();
	} else if(data == 0x40) {
		value = std::numeric_limits<Real>::infinity();
	} else if(data == (0x40|0x01)) {
		value = -std::numeric_limits<Real>::infinity();
	} else if(data == (0x40|0x02|0x01)) {
		value = -Real{};
	} else {
		throw serialisation_error("invalid special real value");
	}
	return value;
}

template<typename Real>
inline
bool check_to_decode_normal_real(std::uint8_t const*& buffer, std::uint_fast8_t& exp_length) {
	if(!(*buffer & 0x80)) {
		throw serialisation_error("only binary encoding supported with real");
	}
	bool sign = *buffer & 0x40;
	if(*buffer & 0x20 || *buffer & 0x10) {
		throw serialisation_error("only base 2 is supported with real");
	}
	if(*buffer & 0x08 || *buffer & 0x04) {
		throw serialisation_error("only 0 scale factor is supported with real");
	}
	if(*buffer & 0x02 && *buffer & 0x01) {
		++buffer;
		exp_length = *buffer;
	} else {
		exp_length = (*buffer & (0x02|0x01))+1;
	}
	++buffer;
	return sign;
}


template<typename Real>
inline
Real decode_normal_real(std::uint8_t const* buffer, std::size_t size) {
	std::uint8_t const* buf{buffer};
	std::uint_fast8_t exp_length{};
	bool sign = check_to_decode_normal_real<Real>(buf, exp_length);
	if(size < std::size_t(buf - buffer + exp_length + 1)) {
		throw serialisation_error("invalid real encoding");
	}
	int exponent = decode_integer<int>(buf, exp_length, sizeof(int));
	buf += exp_length;

	Real mantissa{};
	// reconstruct the mantissa
	for(; buf != buffer+size; ++buf) {
		mantissa = 256*mantissa+*buf;
	}
	Real value = std::ldexp(mantissa, exponent);
	if(sign) {
		value = -value;
	}
	return value;
}

template<typename Real>
inline
Real decode_real(std::uint8_t const* buffer, std::size_t size) {
	Real value{};
	if(size) {
		if(size == 1) {
			value = decode_special_real<Real>(*buffer);
		} else {
			value = decode_normal_real<Real>(buffer, size);
		}
	}
	return value;
}

}

