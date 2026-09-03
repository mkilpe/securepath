// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/byte_order.hpp>
#include <cstddef>

namespace securepath::audio::riff {

//Resource Interchange File Format for PCM audio data

struct chunk_header {
	std::uint8_t chunk_id[4] = {};
	std::uint32_t chunk_size = 0;

	enum { size = 8 };

	std::size_t read(uint8_t const* p, std::size_t s) {
		little_endian_import i(p, s);
		i.translate(chunk_id);
		i.translate(chunk_size);
		return i.position();
	}
	std::size_t write(uint8_t* p, std::size_t s) const {
		little_endian_export e(p, s);
		e.translate(chunk_id);
		e.translate(chunk_size);
		return e.position();
	}
};

struct riff_header {
	riff_header(std::uint32_t size = 0)
	: header{{'R','I','F','F'}, 4+size} //the 4 is for format in this structure and the size is the rest of the data
	, format{'W','A','V','E'} //only wave supported now
	{}

	chunk_header header;
	std::uint8_t format[4];

	enum { size = chunk_header::size + 4 };

	std::size_t read(uint8_t const* p, std::size_t s) {
		little_endian_import i(p, s);
		i.translate_subtype(header);
		i.translate(format);
		return i.position();
	}
	std::size_t write(uint8_t* p, std::size_t s) const {
		little_endian_export e(p, s);
		e.translate_subtype(header);
		e.translate(format);
		return e.position();
	}
};


struct riff_fmt_data {
	std::uint16_t audio_format = 0;
	std::uint16_t channels = 0;
	std::uint32_t sample_rate = 0;
	std::uint32_t byte_rate = 0;      // == sample_rate*channels*bits_per_sample/8
	std::uint16_t block_align = 0;    // == channels*bits_per_sample/8
	std::uint16_t bits_per_sample = 0;

	enum { size = 16 };

	std::size_t read(uint8_t const* p, std::size_t s) {
		little_endian_import i(p, s);
		i.translate(audio_format);
		i.translate(channels);
		i.translate(sample_rate);
		i.translate(byte_rate);
		i.translate(block_align);
		i.translate(bits_per_sample);
		return i.position();
	}
	std::size_t write(uint8_t* p, std::size_t s) const {
		little_endian_export e(p, s);
		e.translate(audio_format);
		e.translate(channels);
		e.translate(sample_rate);
		e.translate(byte_rate);
		e.translate(block_align);
		e.translate(bits_per_sample);
		return e.position();
	}
};

struct riff_fmt {
	chunk_header header = {{'f','m','t',' '}, size - int(chunk_header::size)};
	riff_fmt_data data;

	enum { size = int(chunk_header::size) + int(riff_fmt_data::size) };

	std::size_t read(uint8_t const* p, std::size_t s) {
		little_endian_import i(p, s);
		i.translate_subtype(header);
		i.translate_subtype(data);
		return i.position();
	}
	std::size_t write(uint8_t* p, std::size_t s) const {
		little_endian_export e(p, s);
		e.translate_subtype(header);
		e.translate_subtype(data);
		return e.position();
	}
};

struct riff_data {
	riff_data(octet_vector& d)
	: header{{'d','a','t','a'}, static_cast<std::uint32_t>(d.size())}
	, data(d)
	{}

	chunk_header header;
	octet_vector& data;

	enum { size = chunk_header::size }; //static size only

	std::size_t read(uint8_t const* p, std::size_t s) {
		little_endian_import i(p, s);
		i.translate_subtype(header);
		data.resize(header.chunk_size);
		i.get(data.data(), data.size());
		return i.position();
	}
	std::size_t write(uint8_t* p, std::size_t s) const {
		little_endian_export e(p, s);
		e.translate_subtype(header);
		e.put(data.data(), data.size());
		return e.position();
	}
};

}
