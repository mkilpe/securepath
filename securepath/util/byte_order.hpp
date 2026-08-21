// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <stdexcept>
#include <type_traits>

namespace securepath {

enum class endian { big, little, network = big };

template<endian>
struct endian_convert;

template<>
struct endian_convert<endian::little> {
	template<typename T>
	static void to_endian( std::uint8_t* dest, T v ) noexcept {
		std::make_unsigned_t<T> value(static_cast<std::make_unsigned_t<T>>(v));
		for( std::size_t i{}; i != sizeof(T); ++i ) {
			dest[i] = static_cast<std::uint8_t>( value & 0xFF );
			if constexpr(sizeof(T) > 1) { //to not have undefined behaviour
				value >>= 8;
			}
		}
	}
	template<typename T>
	static T from_endian( std::uint8_t const* source ) noexcept {
		std::make_unsigned_t<T> value{};
		std::size_t shift{};
		for( std::size_t i{}; i != sizeof(T); ++i, shift += 8 ) {
			// shift through the unsigned type: shifting into a signed sign bit
			// is undefined before C++20
			value |= static_cast<std::make_unsigned_t<T>>(source[i]) << shift;

		}
		return static_cast<T>(value);
	}
};

template<>
struct endian_convert<endian::big> {
	template<typename T>
	static void to_endian( std::uint8_t* dest, T v ) noexcept {
		std::make_unsigned_t<T> value(static_cast<std::make_unsigned_t<T>>(v));
		for( std::size_t i{}; i != sizeof(T); ++i ) {
			dest[sizeof(T)-i-1] = static_cast<std::uint8_t>( value & 0xFF );
			if constexpr(sizeof(T) > 1) { //to not have undefined behaviour
				value >>= 8;
			}
		}
	}
	template<typename T>
	static T from_endian( std::uint8_t const* source ) noexcept {
		std::make_unsigned_t<T> value{};
		std::size_t shift{};
		for( std::size_t i{}; i != sizeof(T); ++i, shift += 8 ) {
			value |= static_cast<std::make_unsigned_t<T>>(source[sizeof(T)-i-1]) << shift;
		}
		return static_cast<T>(value);
	}
};

template<typename T, endian e = endian::big>
inline void to_endian(std::uint8_t* dest, T value) noexcept {
	endian_convert<e>::template to_endian<T>(dest, value);
}

template<typename T, endian e = endian::big>
inline T from_endian(std::uint8_t const* source) noexcept {
	return endian_convert<e>::template from_endian<T>(source);
}

template<endian Endian>
class endian_export {
public:
	endian_export(uint8_t* p, std::size_t s) noexcept
	: p_(p)
	, size_(s)
	, pos_()
	{}

	template<typename T>
	void put(T const& v) {
		if( pos_+sizeof(T) > size_ ) {
			throw std::out_of_range("endian_export");
		}
		to_endian<T,Endian>(p_+pos_,v);
		pos_ += sizeof(T);
	}

	template<typename T>
	void put(T const* v, std::size_t s) {
		for(std::size_t i = 0; i != s; ++i) {
			put(v[i]);
		}
	}

	template<typename T>
	void translate(T const& v) {
		put(v);
	}

	template<typename T, std::size_t Size>
	void translate(T const (&arr)[Size]) {
		put(arr, Size);
	}

	template<typename T>
	void translate_subtype(T const& v) {
		pos_ += v.write(p_+pos_, size_-pos_);
	}

	std::size_t position() const noexcept {
		return pos_;
	}
private:
	uint8_t* p_;
	std::size_t size_;
	std::size_t pos_;
};

template<endian Endian>
class endian_import {
public:
	endian_import(uint8_t const* p, std::size_t s) noexcept
	: p_(p)
	, size_(s)
	, pos_()
	{}

	template<typename T>
	T get() {
		if( pos_+sizeof(T) > size_ ) {
			throw std::out_of_range("endian_import");
		}
		T ret{from_endian<T,Endian>(p_+pos_)};
		pos_ += sizeof(T);
		return ret;
	}

	template<typename T>
	void get(T* v, std::size_t s) {
		for(std::size_t i = 0; i != s; ++i) {
			v[i] = get<T>();
		}
	}

	template<typename T>
	void translate(T& v) {
		v = get<T>();
	}

	template<typename T, std::size_t Size>
	void translate(T (&arr)[Size]) {
		get(arr, Size);
	}

	template<typename T>
	void translate_subtype(T& v) {
		pos_ += v.read(p_+pos_, size_-pos_);
	}

	std::size_t position() const noexcept {
		return pos_;
	}
private:
	uint8_t const* p_;
	std::size_t size_;
	std::size_t pos_;
};

using little_endian_export = endian_export<endian::little>;
using big_endian_export = endian_export<endian::big>;
using little_endian_import = endian_import<endian::little>;
using big_endian_import = endian_import<endian::big>;

}

