// SPDX-License-Identifier: MIT

#pragma once

#include "buffered_stream.hpp"
#include "types.hpp"
#include "util.hpp"

#include <securepath/serialisation/codec/decoder.hpp>
#include <securepath/log/detail/util.hpp>
#include <securepath/log/log.hpp>

#include <list>

namespace securepath::serialisation {


/// Limit structure nesting depth, so that recursively decoded types cannot overflow the stack
std::size_t const max_structure_depth{64};

template<typename Stream>
class asn_der_decoder : public decoder {
public:
	asn_der_decoder(Stream& s)
	: s_(s)
	{}

	virtual void decode(bool& b, std::optional<tag_info> tag) {
		int v = 0;
		decode_integer(v, tag, 1, asn_tag::boolean);
		b = static_cast<bool>(v);
	}

	virtual void decode(int64_t& v, std::optional<tag_info> tag, std::uint_fast8_t size_hint) {
		decode_integer(v, tag, size_hint);
	}

	virtual void decode(uint64_t& v, std::optional<tag_info> tag, std::uint_fast8_t size_hint) {
		decode_integer(v, tag, size_hint);
	}

	virtual void decode(double& v, std::optional<tag_info> tag) {
		decode_real(v, tag);
	}

	virtual void decode(integer& v, std::optional<tag_info> tag) {
		decode_integer(v, tag);
	}

	virtual void decode(std::string& s, std::optional<tag_info> tag) {
		decode_string(s, tag, asn_tag::t61string);
	}

	virtual void decode(octet_vector& v, std::optional<tag_info> tag) {
		decode_string(v, tag, asn_tag::octet_string);
	}

	virtual void decode(trailing_data& d) {
		if(seq_pos_.empty()) {
			// trailing data is "the rest of the enclosing sequence"; there is
			// no meaningful extent at the outermost level
			throw serialisation_error("trailing data decoded outside a sequence");
		}
		uint64_t pos = seq_pos_.front();
		if(s_.pos() < pos) {
			octet_vector b(pos - s_.pos());
			s_.read(b.data(), b.size());
			d = trailing_data(std::move(b));
		}
	}

	virtual void decode(time_point& time, std::optional<tag_info> tag) {
		std::string content;
		decode_string(content, tag, asn_tag::generalised_time);
		std::tm t{};

		if(content.size() < 15 || std::sscanf(content.c_str(), "%04d%02d%02d%02d%02d%02d"
			, &t.tm_year, &t.tm_mon, &t.tm_mday
			, &t.tm_hour, &t.tm_min, &t.tm_sec) != 6)
		{
			LOG_WARN("decode: illegal time value");
			throw serialisation_error("illegal time value");
		}

		t.tm_year -= 1900;
		t.tm_mon -= 1;
		//t.tm_isdst = -1;
		std::chrono::milliseconds millis{};
		if(content[14] == '.') {
			int ms = 0;
			if(std::sscanf(content.c_str() + 14, ".%03dZ", &ms) != 1) {
				LOG_WARN("decode: illegal time value, bad fractions");
				throw serialisation_error("illegal time value, bad fractions");
			}
			millis = std::chrono::milliseconds{ms};
		} else if(content[14] != 'Z') {
			LOG_WARN("decode: illegal time value");
			throw serialisation_error("illegal time value");
		}
		std::time_t since_epoch = log::timegm(t);
		if(since_epoch == -1) {
			LOG_WARN("decode: illegal time value, could not convert to time_t");
			throw serialisation_error("illegal time value, could not convert to time_t");
		}
		time = time_point::clock::from_time_t(since_epoch) + millis;
	}

	virtual void start_sequence(std::optional<tag_info> tag) {
		asn_header header = decode_header(get_asn_class(tag), get_tag(tag, asn_tag::sequence));
		if(!header.is_constructed) {
			LOG_WARN("start_sequence: invalid sequence");
			throw serialisation_error("invalid sequence");
		}
		push(header.length);
	}

	virtual void end_sequence() {
		pop();
	}

	virtual void start_explicit_tag(tag_info tag) {
		asn_header header = decode_header(tag.tag_type.value_or(asn_class::context_specific_c), tag.tag);
		if(!header.is_constructed) {
			LOG_WARN("start_explicit_tag: invalid explicit tag");
			throw serialisation_error("invalid explicit tag");
		}
		push(header.length);
	}

	virtual void end_explicit_tag() {
		pop();
	}

	virtual tag_info next_tag() {
		asn_header header = next_header();
		return tag_info{header.asn_class, header.tag};
	}

	virtual bool is_end_of_sequence() const {
		return seq_pos_.empty() ? false : seq_pos_.front() <= s_.pos();
	}

	virtual std::size_t start_peek() {
		return s_.start_peek();
	}

	virtual void end_peek(std::size_t pos, bool commit) {
		s_.end_peek(pos, commit);
	}

	virtual std::uint64_t next_length() {
		std::uint64_t ret = 0;
		try {
			std::uint64_t pos = s_.pos();
			stream_peek_guard<decltype(s_)> g(s_);
			asn_header h = decode_header();
			ret = s_.pos() - pos + h.length;
		} catch(...) {}
		return ret;
	}

	virtual std::uint64_t has_next() {
		std::uint64_t ret = 0;
		try {
			std::uint64_t lenght = next_length();
			if(lenght && s_.readable_bytes(lenght)) {
				ret = lenght;
			}
		} catch(...) {}
		return ret;
	}

	virtual std::uint64_t position() const {
		return s_.pos();
	}

private:
	asn_header next_header() {
		stream_peek_guard<decltype(s_)> g(s_);
		return decode_header();
	}

	void push(std::uint64_t length) {
		if(seq_pos_.size() >= max_structure_depth) {
			throw serialisation_error("structure nesting too deep");
		}
		seq_pos_.push_front(s_.pos()+length);
	}

	void pop() {
		assert(!seq_pos_.empty());
		uint64_t pos = seq_pos_.front();
		seq_pos_.pop_front();
		//todo: slow, fix
		for(;s_.pos() < pos; s_.read()) {}
	}

	std::uint64_t decode_long_tag() {
		std::uint64_t ret{};
		std::uint8_t b = s_.read();
		for(std::size_t i = 0; b & 0x80; ++i, b = s_.read() ) {
			if(i+1 == sizeof(uint64_t)*8/7+1) {
				LOG_WARN("decode_long_tag: too long tag in asn header");
				throw serialisation_error("too long tag in asn header");
			}
			ret = (ret << 7) | (b & 0x7f);
		}
		return (ret << 7) | b;
	}

	std::uint64_t decode_tag(std::uint8_t b) {
		return (b & 0x1f) == 0x1f ? decode_long_tag() : b & 0x1f;
	}

	std::uint64_t decode_long_length(uint8_t b) {
		std::uint_fast8_t size = b & ~std::uint8_t(0x80);
		if(size > sizeof(uint64_t) || size == 0) {
			LOG_WARN("decode_long_length: illegal length in asn header");
			throw serialisation_error("illegal length in asn header");
		}
		std::uint8_t buf[sizeof(uint64_t)];
		s_.read(buf, size);
		return decode_from_octets<std::uint64_t>(buf, size);
	}

	std::uint64_t decode_length() {
		std::uint8_t b = s_.read();
		return b & 0x80 ? decode_long_length(b) : b & ~std::uint8_t(0x80);
	}

	asn_header decode_tag() {
		std::uint8_t b = s_.read();
		asn_header header;
		header.is_constructed = (b & 0x20) != 0;
		header.asn_class = b >> 6;
		header.tag = decode_tag(b);
		header.length = 0;
		return header;
	}

	asn_header decode_header() {
		asn_header header = decode_tag();
		header.length = decode_length();
		auto const max_size = header.is_constructed ? max_constructed_size : max_structure_size;
		if(header.length > max_size) {
			LOG_WARN("received asn structure which has size bigger than the set maximum ({} > {})", header.length, max_size);
			throw serialisation_error("asn structure too big");
		}
		return header;
	}

	asn_header decode_header(asn_class_type asn_class, uint64_t tag) {
		// outside any sequence, absence manifests as clean end of stream;
		// inside a sequence a stream end is truncation and propagates as error
		if(is_end_of_sequence() || (seq_pos_.empty() && !s_.readable_bytes(1))) {
			if(!s_.is_peeking()) {
				LOG_WARN("decode_header: end of sequence detected");
			}
			throw element_not_present("end of sequence when trying to decode header");
		}
		asn_header header = decode_header();
		if(header.asn_class != asn_class || header.tag != tag) {
			if(!s_.is_peeking()) {
				LOG_WARN("decode_header: asn class or tag does not match");
			}
			throw element_not_present("asn class or tag does not match");
		}
		return header;
	}

	template<typename Type>
	void decode_string(Type& s, std::optional<tag_info> tag, uint64_t default_tag) {
		asn_header header = decode_header(get_asn_class(tag), get_tag(tag, default_tag));
		s.resize(header.length);
		s_.read(reinterpret_cast<std::uint8_t*>(s.data()), s.size());
	}

	template<typename Type>
	void decode_integer(Type& s, std::optional<tag_info> tag, std::uint_fast8_t size_hint, uint64_t default_tag = asn_tag::integer) {
		asn_header header = decode_header(get_asn_class(tag), get_tag(tag, default_tag));
		std::uint8_t buf[sizeof(std::uint64_t)+1];
		bool is_signed = std::numeric_limits<Type>::is_signed;
		if(header.length > std::uint64_t(size_hint + static_cast<int>(!is_signed))) {
			LOG_WARN("decode_integer: integer does not fit to given type");
			throw serialisation_error("integer does not fit to given type");
		}
		if(header.length == 0) {
			LOG_WARN("decode_integer: zero length integer");
			throw serialisation_error("integer must be at least one octet");
		}
		s_.read(buf, header.length);
		if((buf[0] & 0x80) && !is_signed) { // signed
			LOG_WARN("decore_integer: unsigned/signed mismatch");
			throw serialisation_error("unsigned/signed mismatch");
		}
		s = serialisation::decode_integer<Type>(buf, header.length, size_hint);
	}

	void decode_integer(integer& s, std::optional<tag_info> tag, uint64_t default_tag = asn_tag::integer) {
		asn_header header = decode_header(get_asn_class(tag), get_tag(tag, default_tag));
		if(header.length == 0) {
			LOG_WARN("decode_integer: zero length integer");
			throw serialisation_error("integer must be at least one octet");
		}
		octet_vector buf(header.length);
		s_.read(buf.data(), header.length);
		s = integer(std::move(buf));
	}

	template<typename Real>
	void decode_real(Real& s, std::optional<tag_info> tag, uint64_t default_tag = asn_tag::real) {
		asn_header header = decode_header(get_asn_class(tag), get_tag(tag, default_tag));
		if(header.length > sizeof(Real)+sizeof(int)+2) {
			LOG_WARN("decode_real: real value too large");
			throw serialisation_error("real value too large");
		}
		std::uint8_t buffer[sizeof(Real)+sizeof(int)+2];
		s_.read(buffer, header.length);
		s = serialisation::decode_real<Real>(buffer, header.length);
	}

private:
	buffered_stream<Stream> s_;
	std::list<std::uint64_t> seq_pos_;
};

}

