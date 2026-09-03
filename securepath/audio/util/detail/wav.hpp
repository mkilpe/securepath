// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/audio/util/audio_data.hpp>
#include <securepath/audio/util/riff_format.hpp>

namespace securepath::audio {

// Most channels the WAV validator accepts and the frame decoder can hold on
// its stack; shared so a file that parses is guaranteed to decode.
inline constexpr std::uint16_t max_supported_channels = 16;

// Validates a parsed WAV format chunk against what this decoder can safely and
// correctly handle, throwing invalid_format on any unsupported or inconsistent
// parameters. data_size is the size of the data chunk in bytes. Kept as a free
// function so malformed inputs can be exercised without crafting a byte stream.
void validate_wav_format(riff::riff_fmt_data const& fmt, std::size_t data_size);

class wav {
public:
	wav(octet_vector& d)
	: data_(d)
	{}

	void load(std::istream& in);
	void save(std::ostream& out, audio::audio_format const& format);

	audio::audio_format format() const;

private:
	void load_chunk(std::istream& in);
	void load_format_chunk(std::istream& in, std::size_t size);
	void load_data_chunk(std::istream& in, std::size_t size);

private:
	octet_vector& data_;
	riff::riff_header header_;
	std::optional<riff::riff_fmt_data> format_;
};

}

