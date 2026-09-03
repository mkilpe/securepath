// SPDX-License-Identifier: MIT

#pragma once

#include "audio_format.hpp"
#include <securepath/util/types.hpp>
#include <securepath/util/span.hpp>

#include <memory>

namespace securepath::audio {

class audio_buffer_base;
class audio_buffer_visitor;

//type-erased buffer that contains the audio format information.
class audio_buffer {
public:
	typedef std::uint_fast32_t uint;

	audio_buffer();
	audio_buffer(audio_format f, std::size_t samples);
	audio_buffer(audio_format f, octet_vector const& data);
	audio_buffer(audio_buffer&&);
	~audio_buffer();

	audio_buffer& operator=(audio_buffer&&);

	audio_format format() const { return format_; }

	uint size() const { return samples_*bytes_per_sample_; }
	uint samples() const { return samples_; }

	uint used_size() const { return used_samples_*bytes_per_sample_; }
	uint used_samples() const { return used_samples_; }

	uint free_size() const { return free_samples()*bytes_per_sample_; }
	uint free_samples() const { return samples()-used_samples(); }

	bool empty() const { return used_samples() == 0; }
	bool full() const { return used_samples() == samples(); }

	void set_used_size(uint s) { used_samples_ = s/bytes_per_sample_; }
	void set_used_samples(uint s) { used_samples_ = s; }

	void conserve(uint bytes) { conserve_samples(bytes/bytes_per_sample_); }
	void conserve_samples(uint samples) { used_samples_ += samples; }

	void consume(uint bytes) { consume_samples(bytes/bytes_per_sample_); }
	void consume_samples(uint samples);

	//these are all based on samples and not bytes
	void add_silence_samples(uint samples);
	void mix(uint pos, audio_buffer const& buf, uint buf_pos, uint length, double mult);
	void scale(uint pos, uint length, double mult);

	template<typename T> T* begin() { return static_cast<T*>(p_); }
	template<typename T> T const* begin() const { return static_cast<T const*>(p_); }
	template<typename T> T* free_begin() { return static_cast<T*>(static_cast<void*>(begin<char>()+used_samples_*bytes_per_sample_)); }
	template<typename T> T const* free_begin() const { return static_cast<T const*>(static_cast<void const*>(begin<char>()+used_samples_*bytes_per_sample_)); }

	void visit(audio_buffer_visitor&);

	audio_buffer copy() const;

	//debug dump
	void dump(std::ostream&);
private:
	audio_format format_;
	void* p_ {};
	std::size_t bytes_per_sample_ {};
	std::size_t samples_ {};
	std::size_t used_samples_ {};
	std::unique_ptr<audio_buffer_base> ptr_;
};

struct audio_buffer_visitor {
	virtual void execute(mutable_span<int8_t>) = 0;
	virtual void execute(mutable_span<uint8_t>) = 0;
	virtual void execute(mutable_span<int16_t>) = 0;
	virtual void execute(mutable_span<float>) = 0;
protected:
	~audio_buffer_visitor() {}
};

}

