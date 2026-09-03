// SPDX-License-Identifier: MIT

#pragma once

#include "audio_buffer.hpp"

#include <cstdint>
#include <cstddef>
#include <stdexcept>

namespace securepath::audio {

struct codec_config {
	std::uint32_t sample_rate = 24000;
	std::uint32_t channels = 1;
	std::uint32_t bit_rate = 64000;
};

class play_codec {
public:
	virtual ~play_codec() {}

	//decode incoming packet, if out_size == 0, use the size of the out buffer
	virtual std::size_t decode(std::uint8_t const* in, std::size_t in_size, audio_buffer& out, std::size_t out_size = 0) = 0;
};

typedef std::unique_ptr<play_codec> play_codec_ptr;

class capture_codec {
public:
	virtual ~capture_codec() {}
	virtual std::size_t encode(audio_buffer& in, std::size_t samples, std::uint8_t* out, std::size_t out_size) = 0;
};

typedef std::unique_ptr<capture_codec> capture_codec_ptr;

struct codec_operation_failed : std::runtime_error {
	using std::runtime_error::runtime_error;
};

}

