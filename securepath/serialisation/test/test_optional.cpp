// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include "util.hpp"
#include "types.hpp"

namespace securepath::serialisation::test {

struct containee {
	std::uint16_t v = 0;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & v;
	}

	bool operator==(containee const c) const {
		return v == c.v;
	}
};

struct container {

	std::uint16_t v;
	std::optional<containee> opt;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & v & opt;
	}

	bool operator==(container const c) const {
		return v == c.v && opt == c.opt;
	}
};

TEST_CASE("optional composite test", "[serialisation][optional]") {
	std::vector<container> vec(2);
	CHECK(check(vec));
}

namespace {

// container as saved before the optional field existed
struct old_container {
	std::uint16_t v = 0;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & v;
	}
};

template<typename To, typename From>
To reser(From from) {
	std::stringstream ss;
	auto ser = serialisation::make_serialiser<serialisation::asn_der_encoder<std::stringstream>>(ss);
	ser & from;
	To to{};
	auto deser = serialisation::make_deserialiser<serialisation::asn_der_decoder<std::stringstream>>(ss);
	deser & to;
	return to;
}

template<typename To>
To deser_bytes(std::initializer_list<std::uint8_t> bytes) {
	std::stringstream ss{std::string(bytes.begin(), bytes.end())};
	To to{};
	auto deser = serialisation::make_deserialiser<serialisation::asn_der_decoder<std::stringstream>>(ss);
	deser & to;
	return to;
}

struct tagged_container {
	std::uint16_t v = 0;
	std::optional<std::uint16_t> opt;
	std::uint16_t after = 0;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & v & serialisation::implicit_tag(1, opt) & after;
	}
};

}

TEST_CASE("absent trailing optional decodes as nullopt", "[serialisation][optional]") {
	old_container old{7};
	container c = reser<container>(old);
	CHECK(c.v == 7);
	CHECK(!c.opt.has_value());
}

TEST_CASE("corrupt optional content throws instead of reading as absent", "[serialisation][optional]") {
	// outer sequence: valid v, then a nested sequence whose integer is
	// zero-length — data is present but malformed, which must not be
	// mistaken for an absent field
	auto load = [] {
		return deser_bytes<container>(
			{ 0x30, 0x09          // container sequence
			, 0x02, 0x02, 0x00, 0x07 // v = 7
			, 0x30, 0x02          // containee sequence
			, 0x02, 0x00 });      // zero-length INTEGER: corrupt
	};
	CHECK_THROWS_AS(load(), serialisation_error);
}

TEST_CASE("tagged optional yields to a differently tagged element", "[serialisation][optional]") {
	// implicit-tagged optional is absent, an untagged element follows: the
	// tag mismatch means "field not present", and the next field must still
	// decode from the same position
	tagged_container c = deser_bytes<tagged_container>(
		{ 0x30, 0x08
		, 0x02, 0x02, 0x00, 0x07   // v = 7
		, 0x02, 0x02, 0x00, 0x09 }); // after = 9 (universal tag, not ctx-1)
	CHECK(c.v == 7);
	CHECK(!c.opt.has_value());
	CHECK(c.after == 9);
}

TEST_CASE("container of optionals cannot loop on a non-advancing element", "[serialisation][optional]") {
	// an absent optional consumes nothing; decoding a sequence whose content
	// never matches used to append nullopt forever until memory ran out
	auto load = [] {
		return deser_bytes<std::vector<std::optional<std::uint16_t>>>(
			{ 0x30, 0x03
			, 0x09, 0x01, 0x00 }); // a REAL: never matches optional<int>
	};
	CHECK_THROWS_AS(load(), serialisation_error);
}

}
