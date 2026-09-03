// SPDX-License-Identifier: MIT


#include "util.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>

namespace securepath::audio {

std::size_t octets_to_sample_count(audio_format const& f, std::size_t octets) {
	return octets*8/f.bits_per_sample;
}

std::size_t length_to_sample_count(audio_format const& f, length_type length_in_ms)
{
	return (f.channels * f.samples_per_second * length_in_ms.count()) / 1000;
}

std::size_t samples_to_octet_count(audio_format const& f, std::size_t samples) {
	return (samples * f.bits_per_sample) / 8;
}

std::size_t length_to_byte_count(audio_format const& f, length_type length_in_ms) {
	return (f.channels * f.samples_per_second * length_in_ms.count() * f.bits_per_sample) / (1000*8);
}

length_type multiple_of_samples_length(length_type size, length_type samples_size)
{
	return length_type{(size/samples_size)*samples_size};
}

length_type audio_buffer_to_length(audio_buffer const& buf) {
	return samples_to_length(buf.format(), buf.used_samples());
}

length_type samples_to_length(audio_format const& f, std::size_t samples) {
	return length_type{samples*1000/(f.channels * f.samples_per_second)};
}

double octets_to_duration(audio_format const& f, std::size_t octets) {
	return double(octets)*8/(f.channels*f.bits_per_sample*f.samples_per_second);
}

double samples_to_duration(audio_format const& f, std::size_t samples) {
	return double(samples)/(f.channels*f.samples_per_second);
}


struct volume_adjust : audio_buffer_visitor {
	volume_adjust(double value, double noise)
	: value_(value)
	, noise_(noise)
	{}

	virtual void execute(mutable_span<int8_t>) { assert(!"not implemented"); }
	virtual void execute(mutable_span<uint8_t>) { assert(!"not implemented"); }
	virtual void execute(mutable_span<float>) { assert(!"not implemented"); }

	virtual void execute(mutable_span<int16_t> s) {
		int noise_threshold = 32767*noise_;
		for(int16_t& v : s) {
			if(std::abs(v) > noise_threshold) {
				int sample = v*value_;
				v = std::clamp(sample, -32767, 32767);
			}
		}
	}

	double value_;
	double noise_;
};

void adjust_volume(audio_buffer& b, double adjust, double noise) {
	volume_adjust v(std::pow(10.0, adjust * 0.05), noise);
	b.visit(v);
}

}
