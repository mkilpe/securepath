// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"
#include "util.hpp"

#include <securepath/serialisation/codec/encoder.hpp>
#include <securepath/log/detail/util.hpp>
#include <securepath/log/log.hpp>

#include <cassert>
#include <deque>

namespace securepath::serialisation {

template<typename Stream>
class asn_der_encoder : public encoder {
public:
	using stream_type = Stream;

	asn_der_encoder(stream_type& stream)
	: stream_(stream)
	{
	}

	virtual void encode(bool v, std::optional<tag_info> t) {
		encode_integer(static_cast<int>(v), t, 1, asn_tag::boolean);
	}

	virtual void encode(int64_t v, std::optional<tag_info> t, std::uint_fast8_t size_hint) {
		encode_integer(v, t, size_hint);
	}

	virtual void encode(uint64_t v, std::optional<tag_info> t, std::uint_fast8_t size_hint) {
		encode_integer(v, t, size_hint);
	}

	virtual void encode(integer const& v, std::optional<tag_info> t) {
		encode_integer(v, t);
	}

	virtual void encode(std::string const& s, std::optional<tag_info> tag) {
		encode_string(s, tag, asn_tag::t61string);
	}

	virtual void encode(octet_vector const& s, std::optional<tag_info> tag) {
		encode_string(s, tag, asn_tag::octet_string);
	}

	virtual void encode(double const& v, std::optional<tag_info> tag) {
		encode_real(v, tag, asn_tag::real);
	}

	virtual void encode(time_point const& time, std::optional<tag_info> tag) {
		std::tm t{};
		if(!log::gmtime(time_point::clock::to_time_t(time), t)) {
			LOG_WARN("encode: cannot convert time");
			throw serialisation_error("cannot convert time");
		}
		char buffer[20] = {};
		std::snprintf(buffer, 15, "%04u%02u%02u%02u%02u%02u"
			, t.tm_year + 1900, t.tm_mon + 1, t.tm_mday
			, t.tm_hour, t.tm_min, t.tm_sec);
		int ms = std::abs(static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count() % 1000));
		if(ms) {
			std::snprintf(buffer + 14, 6, ".%03dZ", ms);
		} else {
			buffer[14] = 'Z';
		}
		encode_string(std::string(buffer), tag, asn_tag::generalised_time);
	}

	virtual void encode(trailing_data const& d) {
		write(d.data().data(), d.data().size());
	}

	virtual void start_sequence(std::optional<tag_info> tag) {
		asn_header header;
		header.asn_class = get_asn_class(tag);
		header.tag = get_tag(tag, asn_tag::sequence);
		header.is_constructed = true;
		push(std::move(header));
	}

	virtual void end_sequence() {
		seq_struct l = pop();
		l.header.length = l.data.size();
		encode_header(l.header);
		if(!l.data.empty()) {
			write(reinterpret_cast<std::uint8_t const*>(l.data.data()), l.data.size());
		}
	}

	virtual void start_explicit_tag(tag_info tag) {
		asn_header header;
		header.asn_class = tag.tag_type.value_or(asn_class::context_specific_c);
		header.tag = tag.tag;
		header.is_constructed = true;
		push(std::move(header));
	}

	virtual void end_explicit_tag() {
		end_sequence();
	}

private:
	struct seq_struct {
		asn_header header;
		std::vector<char> data;
	};

	void encode_tag_first_byte(asn_class_type asn_c, uint64_t tag, bool is_constructed) {
		uint8_t v = (static_cast<uint8_t>(asn_c) << 6) | tag;
		if(is_constructed) {
			v |= 0x20;
		}
		write(&v, 1);
	}

	void encode_long_tag(asn_header const& header) {
		encode_tag_first_byte(header.asn_class, 0x1f, header.is_constructed);

		std::uint8_t buffer[sizeof(header.tag)*8/7+1];
		std::size_t length = encode_to_octets(header.tag, buffer, sizeof(header.tag), false, 7, 0x80);
		buffer[length-1] &= ~static_cast<std::uint8_t>(0x80);
		write(buffer, length);
	}

	void encode_tag(asn_header const& header) {
		if(header.tag > 30) {
			encode_long_tag(header);
		} else {
			encode_tag_first_byte(header.asn_class, header.tag & 0x1f, header.is_constructed);
		}
	}

	void encode_long_length(asn_header const& header) {
		std::uint8_t buffer[sizeof(header.length)];
		std::uint_fast8_t length = encode_to_octets(header.length, buffer, sizeof(header.length), false);
		std::uint8_t v = 0x80 | length;
		write(&v, 1);
		write(buffer, length);
	}

	void encode_length(asn_header const& header) {
		if(header.length > 127) {
			encode_long_length(header);
		} else {
			std::uint8_t v = static_cast<std::uint8_t>(header.length) & ~static_cast<std::uint8_t>(0x80);
			write(&v, 1);
		}
	}

	void encode_header(asn_header const& header) {
		encode_tag(header);
		encode_length(header);
	}

	void write(std::uint8_t const* b, std::size_t size) {
		if(layers_.empty()) {
			if(!stream_.write(reinterpret_cast<char const*>(b), size)) {
				LOG_WARN("write: failed to write to stream");
				throw serialisation_error("failed to write to stream");
			}
		} else {
			seq_struct& s = layers_.front();
			s.data.insert(s.data.end(), b, b+size);
		}
	}

	void push(asn_header info) {
		layers_.push_front(seq_struct{info});
	}

	seq_struct pop() {
		assert(!layers_.empty());
		seq_struct s = std::move(layers_.front());
		layers_.pop_front();
		return s;
	}

	template<typename Type>
	void encode_integer(Type const& value, std::optional<tag_info> tag, std::uint_fast8_t size_hint, uint64_t default_tag = asn_tag::integer) {
		std::uint8_t buffer[sizeof(Type)+1];
		asn_header header;

		header.asn_class = get_asn_class(tag);
		header.tag = get_tag(tag, default_tag);
		header.length = serialisation::encode_integer(value, buffer, size_hint);

		encode_header(header);
		write(buffer, header.length);
	}

	void encode_integer(integer const& value, std::optional<tag_info> tag, uint64_t default_tag = asn_tag::integer) {
		asn_header header;

		header.asn_class = get_asn_class(tag);
		header.tag = get_tag(tag, default_tag);
		header.length = value.data().size();

		encode_header(header);
		write(value.data().data(), header.length);
	}

	template<typename Type>
	void encode_string(Type const& s, std::optional<tag_info> tag, uint64_t default_tag) {
		if(s.size() > max_structure_size) {
			// the decoder refuses primitives above this limit; writing one would
			// produce a document that saves fine but can never be loaded
			throw serialisation_error("string too large to be decodable");
		}
		asn_header header;
		header.asn_class = get_asn_class(tag);
		header.tag = get_tag(tag, default_tag);
		header.length = s.size();
		encode_header(header);
		if(!s.empty()) {
			write(reinterpret_cast<std::uint8_t const*>(s.data()), s.size());
		}
	}

	template<typename Real>
	void encode_real(Real const& value, std::optional<tag_info> tag, uint64_t default_tag) {
		std::uint8_t buffer[sizeof(Real)+sizeof(int)+2];
		asn_header header;

		header.asn_class = get_asn_class(tag);
		header.tag = get_tag(tag, default_tag);
		header.length = serialisation::encode_real(value, buffer);

		encode_header(header);
		write(buffer, header.length);
	}

private:
	stream_type& stream_;
	std::deque<seq_struct> layers_;
};

}

