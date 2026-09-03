// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/serialiser.hpp>
#include <securepath/serialisation/deserialiser.hpp>

#include <bit>
#include <cstdint>
#include <cstddef>
#include <iosfwd>

namespace securepath::audio {

enum sample_type {
	char_t,
	uchar_t,
	short_t,
	float_t,
	int24_t
};

inline
auto& serialise(serialisation::serialiser& s, sample_type const& v) {
	s & int(v);
	return s;
}

inline
auto& serialise(serialisation::deserialiser& s, sample_type& v) {
	int i = 0;
	s & i;
	v = sample_type(i);
	return s;
}

struct audio_format {
	sample_type type = short_t;
	std::uint32_t channels = 1;
	std::uint32_t bits_per_sample = 16;
	std::uint32_t samples_per_second = 24000;
	std::endian endian = std::endian::little;

	template<typename Ser>
	void serialise(Ser& s) {
		serialisation::sequence seq(s);
		seq & type & channels & bits_per_sample & samples_per_second & endian;
	}
};

inline bool operator==(audio_format a1, audio_format a2) {
	return a1.type == a2.type
		&& a1.channels == a2.channels
		&& a1.bits_per_sample == a2.bits_per_sample
		&& a1.samples_per_second == a2.samples_per_second
		&& a1.endian == a2.endian;
}

struct device_config final {
	device_config(audio_format f, std::size_t buf_size)
	: format(f)
	, buffer_size(buf_size)
	, period_size(buffer_size/2)
	{}

	audio_format format;
	std::size_t buffer_size; //in samples
	std::size_t period_size; //in samples
};

}

template <>
struct std::formatter<securepath::audio::audio_format> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }
    auto format(const securepath::audio::audio_format& c, std::format_context& ctx) const {
    	char const* sample_type_name[5] = {"char_t", "uchar_t" , "short_t", "float_t", "int24_t"};
        return std::format_to(ctx.out(), "[{}, {}, {}, {}, {}]", sample_type_name[c.type], c.channels, c.bits_per_sample, c.samples_per_second, c.endian == std::endian::little ? "little" : "big");
    }
};

template <>
struct std::formatter<securepath::audio::device_config> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }
    auto format(const securepath::audio::device_config& c, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "{{{}, {}, {}}}", c.buffer_size, c.period_size, c.format);
    }
};

