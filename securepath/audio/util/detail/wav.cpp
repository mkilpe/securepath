// SPDX-License-Identifier: MIT

#include "wav.hpp"

#include <securepath/log/log.hpp>

#include <istream>
#include <cstring>

namespace securepath::audio {

using namespace securepath::audio::riff;

namespace {
	constexpr std::uint16_t wav_format_pcm = 1;
	constexpr std::uint16_t wav_format_float = 3;
	constexpr std::uint32_t max_sample_rate = 768000;
	// declared chunk sizes are attacker-controlled; bound them before allocating
	constexpr std::size_t max_data_chunk_size = 256u*1024*1024;
	constexpr std::size_t max_fmt_chunk_size = 1024;
}

void validate_wav_format(riff::riff_fmt_data const& fmt, std::size_t data_size) {
	if(fmt.audio_format != wav_format_pcm && fmt.audio_format != wav_format_float) {
		LOG_INFO("unsupported wav audio format tag: {}", fmt.audio_format);
		throw invalid_format("unsupported WAV format; only PCM and IEEE float are supported");
	}
	if(fmt.channels < 1 || fmt.channels > max_supported_channels) {
		LOG_INFO("invalid channel count: {}", fmt.channels);
		throw invalid_format("unsupported channel count");
	}
	if(fmt.sample_rate < 1 || fmt.sample_rate > max_sample_rate) {
		LOG_INFO("invalid sample rate: {}", fmt.sample_rate);
		throw invalid_format("unsupported sample rate");
	}
	if(fmt.audio_format == wav_format_float) {
		if(fmt.bits_per_sample != 32) {
			LOG_INFO("invalid float bits_per_sample: {}", fmt.bits_per_sample);
			throw invalid_format("IEEE float WAV must be 32 bits per sample");
		}
	} else {
		if(fmt.bits_per_sample != 8 && fmt.bits_per_sample != 16 && fmt.bits_per_sample != 24) {
			LOG_INFO("invalid PCM bits_per_sample: {}", fmt.bits_per_sample);
			throw invalid_format("only 8, 16 or 24 bit PCM is supported");
		}
	}
	std::size_t frame_size = std::size_t(fmt.channels) * (fmt.bits_per_sample / 8);
	if(frame_size == 0 || (data_size % frame_size) != 0) {
		LOG_INFO("data size {} is not a multiple of frame size {}", data_size, frame_size);
		throw invalid_format("WAV data size is not a multiple of the frame size");
	}
}

static octet_vector read(std::istream& in, std::size_t size) {
	octet_vector buf(size);
	in.read(reinterpret_cast<char*>(buf.data()), buf.size());
	return in ? buf : octet_vector();
}

void wav::save(std::ostream& out, audio::audio_format const& format) {

	if(format.endian != std::endian::little) {
		throw invalid_format("unsupported endian type");
	}
	if(format.type != audio::uchar_t && format.type != audio::short_t && format.type != audio::float_t) {
		throw invalid_format("wav only supports uchar_t, short_t and float_t sample types");
	}

	using namespace riff;
	riff_header header(std::size_t(riff_fmt::size)+std::size_t(riff_data::size)+data_.size());

	riff_fmt fmt;
	// 1 = PCM, 3 = IEEE float
	fmt.data.audio_format = format.type == audio::float_t ? 3 : 1;
	fmt.data.channels = format.channels;
	fmt.data.sample_rate = format.samples_per_second;
	fmt.data.byte_rate = format.samples_per_second*format.channels*format.bits_per_sample/8;
	fmt.data.block_align = format.channels*format.bits_per_sample/8;
	fmt.data.bits_per_sample = format.bits_per_sample;

	riff_data data(data_);

	octet_vector buf(std::size_t(riff_header::size)+std::size_t(riff_fmt::size)+std::size_t(riff_data::size)+data_.size());
	std::size_t p = header.write(buf.data(), buf.size());
	p += fmt.write(buf.data()+p, buf.size()-p);
	data.write(buf.data()+p, buf.size()-p);

	out.write(reinterpret_cast<char const*>(buf.data()), buf.size());
}

void wav::load(std::istream& in) {
	data_.clear();

	octet_vector buf = read(in, riff_header::size);
	if(buf.size() != riff_header::size) {
		throw invalid_format("truncated RIFF header");
	}
	header_.read(buf.data(), buf.size());

	if(std::strncmp(reinterpret_cast<char const*>(header_.header.chunk_id), "RIFF", 4) != 0) {
		throw invalid_format("not a RIFF file");
	}
	if(std::strncmp(reinterpret_cast<char const*>(header_.format), "WAVE", 4) != 0) {
		throw invalid_format("not a RIFF WAVE file");
	}

	for(;in;) {
		load_chunk(in);
	}

	if(!format_) {
		throw invalid_format("format chunk not found");
	}
	if(data_.empty()) {
		throw invalid_format("data chunk not found");
	}
	validate_wav_format(*format_, data_.size());
}

void wav::load_chunk(std::istream& in) {
	LOG_TRACE("reading chunk header at offset {}", std::size_t(in.tellg()));
	octet_vector buf = read(in, chunk_header::size);

	if(buf.empty() && in.gcount() != 0) {
		// bytes remained but not a whole header: cut off mid-file, not clean EOF
		throw invalid_format("truncated chunk header");
	}
	if(!buf.empty()) {
		chunk_header h;
		h.read(buf.data(), buf.size());
		LOG_INFO("found chunk header '{}' with size '{}'", std::string(h.chunk_id, h.chunk_id+4), h.chunk_size);
		if(std::strncmp(reinterpret_cast<char const*>(h.chunk_id), "fmt ", 4) == 0) {
			load_format_chunk(in, h.chunk_size);
		} else if(std::strncmp(reinterpret_cast<char const*>(h.chunk_id), "data", 4) == 0) {
			load_data_chunk(in, h.chunk_size);
		} else {
			LOG_TRACE("skipping RIFF chunk '{}' ({} bytes)", std::string(h.chunk_id, h.chunk_id+4), h.chunk_size);
			in.seekg(h.chunk_size, std::ios_base::cur);
		}
		if(h.chunk_size % 2 != 0) {
			// RIFF chunks are word-aligned: odd payloads are followed by a pad
			// byte not counted in chunk_size
			in.seekg(1, std::ios_base::cur);
		}
	}
}

void wav::load_format_chunk(std::istream& in, std::size_t size) {
	if(size < riff_fmt_data::size) {
		throw invalid_format("truncated fmt chunk");
	}
	if(size > max_fmt_chunk_size) {
		throw invalid_format("fmt chunk size out of bounds");
	}
	octet_vector buf = read(in, size);
	if(buf.size() != size) {
		throw invalid_format("truncated fmt chunk");
	}
	riff_fmt_data fmt;
	fmt.read(buf.data(), buf.size());
	format_ = fmt;
}

void wav::load_data_chunk(std::istream& in, std::size_t size) {
	if(size > max_data_chunk_size) {
		throw invalid_format("data chunk size out of bounds");
	}
	data_ = read(in, size);
	if(data_.size() != size) {
		throw invalid_format("invalid data chunk; size does not match");
	}
}

audio::audio_format wav::format() const {
	if(!format_) {
		throw invalid_format("format chunk not found");
	}
	auto type = [this]() -> audio::sample_type {
		if(format_->audio_format == 3) {
			return audio::float_t;
		}
		if(format_->bits_per_sample == 8) {
			return audio::uchar_t;
		}
		if(format_->bits_per_sample == 24) {
			return audio::int24_t;
		}
		return audio::short_t;
	};

	return audio::audio_format
		{ type()
		, format_->channels
		, format_->bits_per_sample
		, format_->sample_rate
		, std::endian::little };
}

}
