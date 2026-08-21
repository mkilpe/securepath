// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/types.hpp>

namespace securepath::serialisation {

struct encoder {
	virtual ~encoder() {}

	virtual void encode(bool, std::optional<tag_info>) = 0;
	virtual void encode(std::int64_t, std::optional<tag_info>, std::uint_fast8_t size_hint) = 0;
	virtual void encode(std::uint64_t, std::optional<tag_info>, std::uint_fast8_t size_hint) = 0;
	virtual void encode(double const&, std::optional<tag_info>) = 0;
	virtual void encode(integer const&, std::optional<tag_info>) = 0;
	virtual void encode(std::string const&, std::optional<tag_info>) = 0;
	virtual void encode(octet_vector const&, std::optional<tag_info>) = 0;
	virtual void encode(time_point const&, std::optional<tag_info>) = 0;
	virtual void encode(trailing_data const&) = 0;

	virtual void start_sequence(std::optional<tag_info>) = 0;
	virtual void end_sequence() = 0;

	virtual void start_explicit_tag(tag_info) = 0;
	virtual void end_explicit_tag() = 0;
};

}

