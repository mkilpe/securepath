// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/types.hpp>

namespace securepath::serialisation {

struct decoder {
	virtual ~decoder() {}

	virtual void decode(bool&, std::optional<tag_info>) = 0;
	virtual void decode(int64_t&, std::optional<tag_info>, std::uint_fast8_t size_hint) = 0;
	virtual void decode(uint64_t&, std::optional<tag_info>, std::uint_fast8_t size_hint) = 0;
	virtual void decode(double&, std::optional<tag_info>) = 0;
	virtual void decode(integer&, std::optional<tag_info>) = 0;
	virtual void decode(std::string&, std::optional<tag_info>) = 0;
	virtual void decode(octet_vector&, std::optional<tag_info>) = 0;
	virtual void decode(time_point&, std::optional<tag_info>) = 0;
	virtual void decode(trailing_data&) = 0;

	virtual void start_sequence(std::optional<tag_info>) = 0;
	virtual void end_sequence() = 0;

	virtual void start_explicit_tag(tag_info tag) = 0;
	virtual void end_explicit_tag() = 0;

	virtual tag_info next_tag() = 0;
	virtual bool is_end_of_sequence() const = 0;
	virtual uint64_t has_next() = 0;
	virtual uint64_t next_length() = 0;
	virtual uint64_t position() const = 0;

	virtual std::size_t start_peek() = 0;
	virtual void end_peek(std::size_t, bool commit) = 0;
};

class peek_guard {
public:
	peek_guard(decoder& d)
	: d_(d)
	, pos_(d_.start_peek())
	, ex_count_(std::uncaught_exceptions())
	{}

	peek_guard(peek_guard const&) = delete;
	peek_guard& operator=(peek_guard const&) = delete;

	~peek_guard() {
		d_.end_peek(pos_, ex_count_ == std::uncaught_exceptions());
	}
private:
	decoder& d_;
	std::size_t pos_;
	int ex_count_;
};

}

