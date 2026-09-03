// SPDX-License-Identifier: MIT

#include "audio_data.hpp"
#include "detail/wav.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>
#include <fstream>
#include <vector>

namespace securepath::audio {

static std::string file_extension(std::string const& filename) {
	auto p = filename.find_last_of('.');
	return p != std::string::npos ? filename.substr(p+1) : std::string();
}

audio_data::audio_data(audio::audio_format format, octet_vector data)
: format_(format)
, data_(std::move(data))
{
}

audio_data::audio_data(audio::audio_buffer const& buffer)
: format_(buffer.format())
, data_(buffer.begin<std::uint8_t>(), buffer.begin<std::uint8_t>() + buffer.size())
{
}

static_assert(sizeof(float) == 4);

template<typename T>
static T read_value(std::uint8_t const* src, std::endian endian) {
	T v;
	std::memcpy(&v, src, sizeof(T));
	if (endian != std::endian::native) {
		v = std::byteswap(v);
	}
	return v;
}

template<typename T>
static void write_value(std::uint8_t* dst, T v, std::endian endian) {
	if (endian != std::endian::native) {
		v = std::byteswap(v);
	}
	std::memcpy(dst, &v, sizeof(T));
}

static float read_int24(std::uint8_t const* src, std::endian endian) {
	std::int32_t v = 0;
	if (endian == std::endian::little) {
		v = src[0] | (src[1] << 8) | (static_cast<std::int8_t>(src[2]) << 16);
	} else {
		v = src[2] | (src[1] << 8) | (static_cast<std::int8_t>(src[0]) << 16);
	}
	return v / 8388608.0f;
}

static float read_sample(std::uint8_t const* src, audio::audio_format const& fmt) {
	switch(fmt.type) {
	case audio::char_t:  return static_cast<std::int8_t>(*src) / 128.0f;
	case audio::uchar_t: return (*src - 128) / 128.0f;
	case audio::short_t: return read_value<std::int16_t>(src, fmt.endian) / 32768.0f;
	case audio::float_t: return std::bit_cast<float>(read_value<std::uint32_t>(src, fmt.endian));
	case audio::int24_t: return read_int24(src, fmt.endian);
	}
	return 0.f;
}

// quantise to an integer sample using the same scale the read side divides by,
// so integer -> float -> integer round-trips exactly; rounds instead of
// truncating and clamps the +1.0 edge into range
template<typename T>
static T quantise(float v, float scale, long min, long max) {
	return static_cast<T>(std::clamp(std::lrintf(v * scale), min, max));
}

static void write_sample(std::uint8_t* dst, float v, audio::audio_format const& fmt) {
	if(!std::isfinite(v)) {
		// NaN passes through std::clamp unchanged, and float -> int of NaN/Inf is UB
		v = 0.0f;
	}
	v = std::clamp(v, -1.0f, 1.0f);
	switch(fmt.type) {
	case audio::char_t:  *reinterpret_cast<std::int8_t*>(dst) = quantise<std::int8_t>(v, 128.0f, -128, 127); break;
	case audio::uchar_t: *dst = quantise<std::uint8_t>(v + 1.0f, 128.0f, 0, 255); break;
	case audio::short_t: write_value<std::int16_t>(dst, quantise<std::int16_t>(v, 32768.0f, -32768, 32767), fmt.endian); break;
	case audio::float_t: write_value<std::uint32_t>(dst, std::bit_cast<std::uint32_t>(v), fmt.endian); break;
	case audio::int24_t: break;
	}
}

static float mix_channels(float const* channels, std::uint32_t count) {
	float v = 0.f;
	for(std::uint32_t i = 0; i != count; ++i) {
		v += channels[i];
	}
	return v / float(count);
}

static float remap_channel(float const* src_channels, std::uint32_t src_ch, std::uint32_t dst_ch, std::uint32_t ch) {
	if(dst_ch < src_ch) {
		return mix_channels(src_channels, src_ch);
	}
	if(ch < src_ch) {
		return src_channels[ch];
	}
	return src_channels[0];
}

// Decode source bytes to interleaved float samples remapped to dst_ch channels.
static std::vector<float> decode_frames(octet_vector const& data, audio::audio_format const& src, std::uint32_t dst_ch) {
	std::uint32_t src_stride = src.bits_per_sample / 8;
	std::size_t src_frame = std::size_t{src_stride} * src.channels;
	std::size_t num_frames = src_frame ? data.size() / src_frame : 0;

	std::vector<float> out(num_frames * dst_ch);
	for(std::size_t f = 0; f != num_frames; ++f) {
		auto* p = data.data() + f * src_frame;

		float channels[max_supported_channels] = {};
		for(std::uint32_t c = 0; c != src.channels; ++c) {
			channels[c] = read_sample(p + c * src_stride, src);
		}

		for(std::uint32_t c = 0; c != dst_ch; ++c) {
			out[f * dst_ch + c] = remap_channel(channels, src.channels, dst_ch, c);
		}
	}
	return out;
}

// Rate conversion of interleaved float samples by linear interpolation.
static std::vector<float> convert_rate(std::vector<float> const& in, std::uint32_t channels, std::uint32_t src_rate, std::uint32_t dst_rate) {
	std::size_t src_frames = channels ? in.size() / channels : 0;
	if(src_frames == 0) {
		return {};
	}
	// Round to the nearest frame count so the duration is preserved
	std::size_t dst_frames = std::max<std::size_t>(1, (src_frames * dst_rate + src_rate / 2) / src_rate);

	std::vector<float> out(dst_frames * channels);
	double const step = double(src_rate) / dst_rate;
	for(std::size_t f = 0; f != dst_frames; ++f) {
		double pos = double(f) * step;
		auto i0 = std::min(static_cast<std::size_t>(pos), src_frames - 1);
		auto i1 = std::min(i0 + 1, src_frames - 1);
		float frac = static_cast<float>(pos - double(i0));

		for(std::uint32_t c = 0; c != channels; ++c) {
			float a = in[i0 * channels + c];
			float b = in[i1 * channels + c];
			out[f * channels + c] = a + (b - a) * frac;
		}
	}
	return out;
}

static octet_vector encode_frames(std::vector<float> const& samples, audio::audio_format const& target) {
	std::uint32_t dst_stride = target.bits_per_sample / 8;
	octet_vector out(samples.size() * dst_stride);
	for(std::size_t i = 0; i != samples.size(); ++i) {
		write_sample(out.data() + i * dst_stride, samples[i], target);
	}
	return out;
}

void audio_data::resample(audio::audio_format const& target) {
	if(format_.channels > max_supported_channels) {
		throw std::runtime_error("Too many channels, only 16 supported");
	}
	if(format_.samples_per_second != target.samples_per_second
		&& (format_.samples_per_second == 0 || target.samples_per_second == 0)) {
		throw invalid_format("cannot resample from/to a zero sample rate");
	}

	auto samples = decode_frames(data_, format_, target.channels);
	if(format_.samples_per_second != target.samples_per_second) {
		samples = convert_rate(samples, target.channels, format_.samples_per_second, target.samples_per_second);
	}
	data_ = encode_frames(samples, target);
	format_ = target;
}

void audio_data::load(std::string const& file, audio::audio_format format, file_format ff) {
	load(file, ff);
	if(format_ != format) {
		resample(format);
	}	
}

void audio_data::load(std::string const& file, file_format ff) {
	if(ff == auto_format && file_extension(file) == "wav") {
		ff = wav;
	}
	if(ff == wav) {
		std::ifstream in(file, std::ios_base::binary);
		if(!in) {
			throw std::runtime_error("failed to open file: " + file);
		}
		audio::wav w(data_);
		w.load(in);
		format_ = w.format();
	} else {
		throw invalid_format("format not supported");
	}
}

void audio_data::save(std::string const& file, file_format ff) {
	if(ff == auto_format && file_extension(file) == "wav") {
		ff = wav;
	}
	if(ff == wav) {
		std::ofstream out(file, std::ios_base::binary);
		if(!out) {
			throw std::runtime_error("failed to open file: " + file);
		}
		audio::wav w(data_);
		w.save(out, format_);
	} else {
		throw invalid_format("format not supported");
	}
}

void audio_data::save(std::string const& file, audio::audio_format const& format, file_format ff) {
	audio_data copy = *this;
	if(copy.format_ != format) {
		copy.resample(format);
	}
	copy.save(file, ff);
}

audio::audio_format audio_data::format() const {
	return format_;
}

octet_vector audio_data::data() const {
	return data_;
}

audio::audio_buffer load_file_to_buffer(std::string const& file, audio_data::file_format f) {
	audio_data pcm;
	pcm.load(file, f);
	return audio::audio_buffer(pcm.format(), pcm.data());
}

}
