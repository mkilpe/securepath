// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/types.hpp>
#include <securepath/util/types.hpp>

#include <cassert>
#include <cstring>
#include <string>

namespace securepath::serialisation {

template<typename Stream>
class buffered_stream {
public:
	using stream_type = Stream;

	buffered_stream(stream_type& s)
	: stream_(s)
	, look_ahead_pos_()
	, real_pos_()
	, peek_count_()
	{}

	std::uint8_t read() {
		std::uint8_t b;
		read(&b,1);
		return b;
	}

	std::size_t read(std::uint8_t* buf, std::size_t s) {
		std::size_t ps = read_from_buffer(buf, s);
		if(ps != s) {
			ps += read_from_stream(buf+ps, s-ps);
		}
		return ps;
	}

	std::size_t read_from_buffer(std::uint8_t* buf, std::size_t s) {
		std::size_t rs = 0;
		if(look_ahead_pos_ < buffer_.size()) {
			rs = std::min(s, buffer_.size()-look_ahead_pos_);
			std::memcpy(buf, buffer_.data()+look_ahead_pos_, rs);
			look_ahead_pos_ += rs;
			if(!peek_count_ && look_ahead_pos_ == buffer_.size()) {
				real_pos_ += look_ahead_pos_;
				look_ahead_pos_ = 0;
				buffer_.clear();
			}
		}
		return rs;
	}

	std::size_t read_from_stream(std::uint8_t* buf, std::size_t s) {
		// notice: this is broken if the stream/deserialiser doesn't get re-constructed after failure
		// as this might make a partial read and throw the data away
		if(!stream_.read(reinterpret_cast<char*>(buf), s)) {
			throw serialisation_error("end of stream");
		}
		if(peek_count_) {
			buffer_.insert(buffer_.end(), buf, buf+s);
			look_ahead_pos_ += s;
		} else {
			real_pos_ += s;
		}
		return s;
	}

	// true when s bytes can be read from the current position; a pure query,
	// buffered bytes stay readable. On a short stream any partially read bytes
	// are lost (the stream cannot be rewound), matching the previous behaviour.
	bool readable_bytes(std::size_t s) {
		std::size_t buffered = 0;
		if(look_ahead_pos_ < buffer_.size()) {
			buffered = buffer_.size()-look_ahead_pos_;
		}
		if(buffered >= s) {
			return true;
		}
		std::size_t const more_required = s-buffered;
		// read straight into the buffer tail; shrink back on a short read so
		// the query allocates and copies nothing extra
		std::size_t const old_size = buffer_.size();
		buffer_.resize(old_size + more_required);
		if(!stream_.read(reinterpret_cast<char*>(buffer_.data() + old_size), more_required)) {
			buffer_.resize(old_size);
			return false;
		}
		return true;
	}

	bool is_peeking() const {
		return peek_count_ > 0;
	}

	std::size_t start_peek() {
		++peek_count_;
		return look_ahead_pos_;
	}

	void end_peek(std::size_t pos, bool commit = false) {
		assert(peek_count_);
		--peek_count_;
		if(!commit) {
			look_ahead_pos_ = pos;
		}
	}

	std::uint64_t pos() const {
		return real_pos_ + look_ahead_pos_;
	}
private:
	stream_type& stream_;
	octet_vector buffer_;
	std::size_t look_ahead_pos_;
	std::uint64_t real_pos_;
	int peek_count_;
};

template<typename Stream>
class stream_peek_guard {
public:
	stream_peek_guard(Stream& s)
	: s_(s)
	, p_(s.start_peek())
	{}
	~stream_peek_guard() {
		s_.end_peek(p_);
	}
private:
	Stream& s_;
	std::size_t p_;
};

}

