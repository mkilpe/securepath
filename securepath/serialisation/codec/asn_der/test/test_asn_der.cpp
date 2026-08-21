// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "util.hpp"

namespace securepath::serialisation::test {

TEST_CASE("asn_der integer", "[asn_der]") {

	CHECK(check<bool>(false, {0x01, 0x01, 0x00}));
	CHECK(check<bool>(true, {0x01, 0x01, 0x01}));
	CHECK(check_integer<int64_t>(0, {0x02, 0x01, 0x00}));
	CHECK(check_integer<int64_t>(-1, {0x02, 0x01, 0xFF}));
	CHECK(check_integer<int64_t>(127, {0x02, 0x01, 0x7F}));
	CHECK(check_integer<int64_t>(128, {0x02, 0x02, 0x00, 0x80}));
	CHECK(check_integer<int64_t>(255, {0x02, 0x02, 0x00, 0xFF}));
	CHECK(check_integer<int64_t>(256, {0x02, 0x02, 0x01, 0x00}));
	CHECK(check_integer<int64_t>(-128, {0x02, 0x01, 0x80}));
	CHECK(check_integer<int64_t>(-129, {0x02, 0x02, 0xFF, 0x7F}));
	CHECK(check_integer<int64_t>(256, {0x02, 0x02, 0x01, 0x00}));
	CHECK(check_integer<uint32_t>(std::numeric_limits<uint32_t>::max(), {0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}));
	CHECK(check_integer<int32_t>(std::numeric_limits<int32_t>::min(), {0x02, 0x04, 0x80, 0x00, 0x00, 0x00}));
	CHECK(check_integer<uint64_t>(std::numeric_limits<uint64_t>::max(), {0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
	CHECK(check_integer<int64_t>(std::numeric_limits<int64_t>::min(), {0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
	CHECK(check<integer>(integer(octet_vector{0x00, 0xFF}), {0x02, 0x02, 0x00, 0xFF}));
}

TEST_CASE("asn_der real", "[asn_der]") {
	CHECK(check_real<double>(6.0, {0x09, 0x03, 0x80, 0x01, 0x03}));
	CHECK(check_real<double>(0.0, {0x09, 0x00}));
	CHECK(check_real<double>(0.1, {0x09, 0x09, 0x80, 0xC9, 0x0C, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCD}));
	CHECK(check_real<double>(-0.1, {0x09, 0x09, 0xC0, 0xC9, 0x0C, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCD}));
	CHECK(check_real<double>(123456789.0, {0x09, 0x06, 0x80, 0x00, 0x07, 0x5B, 0xCD, 0x15}));
	CHECK(check_real<double>(9.22337203685e+18, {0x09, 0x09, 0x80, 0x0D, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xB9}));
	CHECK(check_real<double>(65536, {0x09, 0x03, 0x80, 0x10, 0x01}));

	CHECK(check_real<double>(-0.0, {0x09, 0x01, 0x43}));
	CHECK(check_real<double>(std::numeric_limits<double>::quiet_NaN(), {0x09, 0x01, 0x42}));
	CHECK(check_real<double>(std::numeric_limits<double>::infinity(), {0x09, 0x01, 0x40}));
	CHECK(check_real<double>(-std::numeric_limits<double>::infinity(), {0x09, 0x01, 0x41}));
}


TEST_CASE("asn_der string", "[asn_der]") {

	CHECK(check<std::string>("", {0x14, 0x00}));
	CHECK(check<std::string>("test string", {0x14, 0x0B, 0x74, 0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67}));
	CHECK(check<octet_vector>({}, {0x04, 0x00}));
	CHECK(check<octet_vector>({0xFF, 0x00, 0x01, 0xE5, 0xDD}, {0x04, 0x05, 0xFF, 0x00, 0x01, 0xE5, 0xDD}));
	CHECK(check<octet_vector>(octet_vector(12345, 'a')));
}

TEST_CASE("asn_der time_point", "[asn_der]") {

	time_point p = time_point::clock::now();
	//serialisation clamps the precision to milliseconds
	CHECK(check<time_point>(p, {}, [](auto a, auto b){
		return std::chrono::duration_cast<std::chrono::milliseconds>(a.time_since_epoch()).count() ==
			std::chrono::duration_cast<std::chrono::milliseconds>(b.time_since_epoch()).count();
	}));

}

TEST_CASE("asn_der implicit tag", "[asn_der]") {

	CHECK(check_integer<int64_t>(0, tag_info{std::nullopt,1}, {0x81, 0x01, 0x00}));
	CHECK(check_integer<int64_t>(0, tag_info{std::nullopt,386}, {0x9F, 0x83, 0x02, 0x01, 0x00}));
	CHECK(check_integer<int64_t>(127, tag_info{std::nullopt,123456}, {0x9F, 0x87, 0xC4, 0x40, 0x01, 0x7F}));
	CHECK(check<std::string>("test", tag_info{std::nullopt,12}, {0x8C, 0x04, 0x74, 0x65, 0x73, 0x74}));
	CHECK(check<octet_vector>({0xFF, 0x00, 0x01, 0xE5, 0xDD}, tag_info{std::nullopt,std::numeric_limits<uint64_t>::max()}, {0x9F, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x05, 0xFF, 0x00, 0x01, 0xE5, 0xDD}));
	CHECK(check_integer<int64_t>(0, tag_info{asn_class::context_specific_c,1}, {0x81, 0x01, 0x00}));
	CHECK(check_integer<int64_t>(127, tag_info{asn_class::application_c,22}, {0x56, 0x01, 0x7F}));
	CHECK(check<std::string>("test", tag_info{asn_class::private_c,11123243}, {0xDF, 0x85, 0xA6, 0xF4, 0x2B, 0x04, 0x74, 0x65, 0x73, 0x74}));
	CHECK(check<octet_vector>({0xFF, 0x00, 0x01, 0xE5, 0xDD}, tag_info{asn_class::private_c,111}, {0xDF, 0x6F, 0x05, 0xFF, 0x00, 0x01, 0xE5, 0xDD}));

}

TEST_CASE("asn_der sequence", "[asn_der]") {

	std::stringstream str;
	int64_t v = 0;
	asn_der_encoder<std::stringstream> encoder(str);
	encoder.start_sequence(std::nullopt);
	encoder.encode(v, std::nullopt, sizeof(v));
	encoder.end_sequence();
	std::string enc{{0x30, 0x03, 0x02, 0x01, 0x00}};
	bool ret = str.str() == enc;
	CHECK(ret);
	asn_der_decoder<std::stringstream> decoder(str);
	decoder.start_sequence(std::nullopt);
	decoder.decode(v, std::nullopt, sizeof(v));
	decoder.end_sequence();

}

TEST_CASE("asn_der explicit tag", "[asn_der]") {

	std::stringstream str;
	int64_t v = 0;
	asn_der_encoder<std::stringstream> encoder(str);
	encoder.start_explicit_tag(tag_info{asn_class::application_c, 1});
	encoder.encode(v, std::nullopt, sizeof(v));
	encoder.end_explicit_tag();
	std::string enc{{0x61, 0x03, 0x02, 0x01, 0x00}};
	bool ret = str.str() == enc;
	CHECK(ret);
	asn_der_decoder<std::stringstream> decoder(str);
	decoder.start_explicit_tag(tag_info{asn_class::application_c, 1});
	decoder.decode(v, std::nullopt, sizeof(v));
	decoder.end_explicit_tag();

}

TEST_CASE("asn_der constructed size limit is separate from primitive limit", "[asn_der]") {
	// a sequence header may declare more than the primitive cap (a large
	// document is mostly one big outer sequence), a primitive may not
	// (its declared length is allocated up front)
	auto make_header = [](std::uint8_t tag_byte, std::uint32_t length) {
		std::string s;
		s.push_back(static_cast<char>(tag_byte));
		s.push_back(static_cast<char>(0x84)); // long form, 4 length octets
		s.push_back(static_cast<char>(length >> 24));
		s.push_back(static_cast<char>(length >> 16));
		s.push_back(static_cast<char>(length >> 8));
		s.push_back(static_cast<char>(length));
		return s;
	};
	std::uint32_t const over_primitive = 3*1024*1024;

	{
		// 3 MB sequence: accepted (content missing, but the header must pass)
		std::stringstream str{make_header(0x30, over_primitive)};
		asn_der_decoder<std::stringstream> decoder(str);
		CHECK_NOTHROW(decoder.start_sequence(std::nullopt));
	}
	{
		// 3 MB octet string: rejected before any allocation
		std::stringstream str{make_header(0x04, over_primitive)};
		asn_der_decoder<std::stringstream> decoder(str);
		octet_vector v;
		CHECK_THROWS_AS(decoder.decode(v, std::nullopt), serialisation_error);
	}
}

TEST_CASE("asn_der encoder refuses strings above the decodable limit", "[asn_der]") {
	std::stringstream str;
	asn_der_encoder<std::stringstream> encoder(str);
	std::string big(max_structure_size + 1, 'x');
	CHECK_THROWS_AS(encoder.encode(big, std::nullopt), serialisation_error);
}

TEST_CASE("asn_der trailing data outside a sequence throws", "[asn_der]") {
	// used to dereference the front of an empty sequence-boundary list
	std::stringstream str{std::string{0x02, 0x01, 0x00}};
	asn_der_decoder<std::stringstream> decoder(str);
	trailing_data d;
	CHECK_THROWS_AS(decoder.decode(d), serialisation_error);
}

}
