// SPDX-License-Identifier: MIT

#include "audio_buffer.hpp"

#include <securepath/util/conversions.hpp>

#include <cassert>
#include <limits>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <algorithm>
#include <ostream>
#include <print>

namespace securepath::audio {

typedef std::uint_fast32_t uint;

class audio_buffer_base {
public:
	virtual ~audio_buffer_base() {}
	virtual void add_silence_samples(uint samples, uint already_used_samples) = 0;
	virtual void mix(uint start, uint end, audio_buffer const& other, uint other_pos, double mult) = 0;
	virtual void scale(uint start, uint end, double mult) = 0;
	virtual void visit(audio_buffer_visitor&, uint already_used_samples) = 0;
};

template<typename T>
struct audio_buffer_typed : public audio_buffer_base {
	// lowest() (not min(), which is the smallest positive value for floats)
	audio_buffer_typed(std::size_t size, T silence)
	: data_(size)
	, silence_(silence)
	, min_(std::numeric_limits<T>::lowest())
	, max_(std::numeric_limits<T>::max())
	{}

	virtual void add_silence_samples(uint samples, uint already_used_samples) {
		std::fill_n(data_.data()+already_used_samples, samples, silence_);
	}

	virtual void visit(audio_buffer_visitor& v, uint already_used_samples) {
		v.execute(mutable_span<T>(data_.data(), data_.data()+already_used_samples));
	}

	virtual void mix(uint start, uint end, audio_buffer const& other, uint other_pos, double mult) {
		// double holds every supported sample type exactly
		T const* o_p = other.begin<T>() + other_pos;
		for(T* p = data_.data() + start; start != end; ++start, ++p, ++o_p) {
			double const v = (double(*p) + double(*o_p)) * mult;
			*p = static_cast<T>(std::clamp(v, double(min_), double(max_)));
		}
	}

	virtual void scale(uint start, uint end, double mult) {
		for(T* p = data_.data() + start; start != end; ++start, ++p) {
			*p = static_cast<T>(std::clamp(double(*p) * mult, double(min_), double(max_)));
		}
	}

	std::vector<T> data_;
	T const silence_;
	T const min_;
	T const max_;
};

std::unique_ptr<audio_buffer_base> construct_typed_buffer(sample_type t, std::size_t samples, void*& p) {
	std::unique_ptr<audio_buffer_base> ret;
	if( t == char_t ) {
		auto* ptr = new audio_buffer_typed<int8_t>(samples, 0);
		p = &ptr->data_[0];
		ret.reset(ptr);
	} else if( t == uchar_t ) {
		auto* ptr = new audio_buffer_typed<uint8_t>(samples, 128);
		p = &ptr->data_[0];
		ret.reset(ptr);
	} else if( t == short_t ) {
		auto* ptr = new audio_buffer_typed<int16_t>(samples, 0);
		p = &ptr->data_[0];
		ret.reset(ptr);
	} else if( t == float_t ) {
		auto* ptr = new audio_buffer_typed<float>(samples, 0);
		p = &ptr->data_[0];
		ret.reset(ptr);
	} else {
		throw std::logic_error("unsupported audio buffer type");
	}
	return ret;
}

// bytes per sample for the in-memory representation; also rejects formats
// whose bits_per_sample disagrees with the storage type, which would desync
// every byte-based size computation from the actual allocation
static std::size_t checked_bytes_per_sample(audio_format const& f) {
	std::size_t expected = 0;
	if(f.type == char_t || f.type == uchar_t) {
		expected = 1;
	} else if(f.type == short_t) {
		expected = 2;
	} else if(f.type == float_t) {
		expected = 4;
	} else {
		throw std::invalid_argument("unsupported audio buffer sample type");
	}
	if(f.bits_per_sample != expected*8) {
		throw std::invalid_argument("bits_per_sample does not match the sample type");
	}
	return expected;
}

static std::size_t checked_sample_count(audio_format const& f, std::size_t data_size) {
	std::size_t const sample_size = checked_bytes_per_sample(f);
	if(data_size % sample_size != 0) {
		throw std::invalid_argument("data size is not a multiple of the sample size");
	}
	return data_size / sample_size;
}

audio_buffer::audio_buffer(audio_format f, std::size_t samples)
: format_(f)
, bytes_per_sample_(checked_bytes_per_sample(f))
, samples_(samples)
, used_samples_()
, ptr_( construct_typed_buffer(f.type, samples, p_) )
{
}

audio_buffer::audio_buffer(audio_format f, octet_vector const& data)
: audio_buffer(f, checked_sample_count(f, data.size()))
{
	std::memcpy(begin<std::uint8_t>(), data.data(), data.size());
	set_used_size(data.size());
}

audio_buffer::audio_buffer(audio_buffer&&) = default;
audio_buffer& audio_buffer::operator=(audio_buffer&&) = default;

audio_buffer::audio_buffer() = default;
audio_buffer::~audio_buffer() = default;

void audio_buffer::consume_samples(uint samples) {
	if(samples == used_samples_) {
		used_samples_ = 0;
	}
	else {
		assert(samples < used_samples_);
		uint length = samples*bytes_per_sample_;
		std::memmove(p_, begin<char>()+length, samples_*bytes_per_sample_-length);
		used_samples_ -= samples;
	}
}

void audio_buffer::add_silence_samples(uint samples) {
	assert(samples <= samples_ - used_samples_);
	ptr_->add_silence_samples(samples, used_samples_);
	used_samples_ += samples;
}

void audio_buffer::mix(uint pos, audio_buffer const& buf, uint buf_pos, uint length, double mult) {
	if(buf.format_.type != format_.type) {
		throw std::invalid_argument("mixing buffers of different sample types");
	}
	//todo: consider real error handling
	assert(pos+length <= used_samples_);
	assert(buf_pos + length <= buf.used_samples());
	ptr_->mix(pos, pos+length, buf, buf_pos, mult);
}

void audio_buffer::scale(uint pos, uint length, double mult) {
	assert(pos+length <= used_samples_);
	ptr_->scale(pos, pos+length, mult);
}

void audio_buffer::visit(audio_buffer_visitor& v) {
	ptr_->visit(v, used_samples_);
}

audio_buffer audio_buffer::copy() const {
	audio_buffer b(format_, samples_);
	std::copy(begin<std::uint8_t>(), free_begin<std::uint8_t>(), b.begin<std::uint8_t>());
	b.set_used_samples(used_samples());
	return b;
}

void audio_buffer::dump(std::ostream& out) {
	std::vector<std::uint8_t> data(begin<std::uint8_t>(), free_begin<std::uint8_t>());
	std::print(out, "{}\n\n{}", format_ , to_hex(data));
}

}
