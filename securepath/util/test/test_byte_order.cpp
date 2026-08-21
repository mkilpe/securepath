// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/byte_order.hpp>

namespace securepath::test {

uint8_t const little_endian_data1[] = {0x88,0xFF};
uint8_t const little_endian_data2[] = {0xFF,0x0,0x0,0x01};
uint8_t const little_endian_data3[] = {0xF0,0xDE,0xBC,0x9A,0x78,0x56,0x34,0x12};
uint8_t const big_endian_data1[] = {0xFF,0x88};
uint8_t const big_endian_data2[] = {0x01,0x0,0x0,0xFF};
uint8_t const big_endian_data3[] = {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0};

uint16_t const value1 = 0xFF88;
uint32_t const value2 = 0x010000FF;
uint64_t const value3 = 0x123456789ABCDEF0LL;

TEST_CASE("byte_order basics", "[byte_order]") {

	CHECK((from_endian<uint16_t, endian::little>(little_endian_data1)) == value1);
	CHECK((from_endian<uint32_t, endian::little>(little_endian_data2)) == value2);
	CHECK((from_endian<uint64_t, endian::little>(little_endian_data3)) == value3);
	CHECK((from_endian<uint16_t, endian::big>(big_endian_data1)) == value1);
	CHECK((from_endian<uint32_t, endian::big>(big_endian_data2)) == value2);
	CHECK((from_endian<uint64_t, endian::big>(big_endian_data3)) == value3);
	uint8_t array[8];
	to_endian<uint16_t, endian::little>(array, value1);
	CHECK((from_endian<uint16_t, endian::little>(array)) == value1);
	to_endian<uint32_t, endian::little>(array, value2);
	CHECK((from_endian<uint32_t, endian::little>(array)) == value2);
	to_endian<uint64_t, endian::little>(array, value3);
	CHECK((from_endian<uint64_t, endian::little>(array)) == value3);
	to_endian<uint16_t, endian::big>(array, value1);
	CHECK((from_endian<uint16_t, endian::big>(array)) == value1);
	to_endian<uint32_t, endian::big>(array, value2);
	CHECK((from_endian<uint32_t, endian::big>(array)) == value2);
	to_endian<uint64_t, endian::big>(array, value3);
	CHECK((from_endian<uint64_t, endian::big>(array)) == value3);

}


TEST_CASE("byte_order signed basics", "[byte_order]") {
	uint8_t array[8];
	to_endian<int16_t, endian::little>(array, value1/2);
	CHECK((from_endian<int16_t, endian::little>(array)) == value1/2);
	to_endian<int16_t, endian::little>(array, -value1/2);
	CHECK((from_endian<int16_t, endian::little>(array)) == -value1/2);
	to_endian<int32_t, endian::little>(array, value2);
	CHECK((from_endian<int32_t, endian::little>(array)) == value2);
	to_endian<int32_t, endian::little>(array, -value2);
	CHECK((from_endian<int32_t, endian::little>(array)) == -int32_t(value2));
	to_endian<int64_t, endian::little>(array, value3);
	CHECK((from_endian<int64_t, endian::little>(array)) == value3);
	to_endian<int64_t, endian::little>(array, -value3);
	CHECK((from_endian<int64_t, endian::little>(array)) == -int64_t(value3));

	to_endian<int16_t, endian::big>(array, value1/2);
	CHECK((from_endian<int16_t, endian::big>(array)) == value1/2);
	to_endian<int16_t, endian::big>(array, -value1/2);
	CHECK((from_endian<int16_t, endian::big>(array)) == -value1/2);
	to_endian<int32_t, endian::big>(array, value2);
	CHECK((from_endian<int32_t, endian::big>(array)) == value2);
	to_endian<int32_t, endian::big>(array, -value2);
	CHECK((from_endian<int32_t, endian::big>(array)) == -int32_t(value2));
	to_endian<int64_t, endian::big>(array, value3);
	CHECK((from_endian<int64_t, endian::big>(array)) == value3);
	to_endian<int64_t, endian::big>(array, -value3);
	CHECK((from_endian<int64_t, endian::big>(array)) == -int64_t(value3));
}

TEST_CASE("byte_order export import", "[byte_order]") {

	uint8_t array[6];
	little_endian_export e(array, sizeof(array));
	CHECK(e.position() == 0);
	e.put(value2);
	CHECK(e.position() == 4);
	e.put(value1);
	CHECK(e.position() == 6);
	CHECK_THROWS_AS(e.put(uint8_t(0)), std::out_of_range);
	little_endian_import i(array, sizeof(array));
	CHECK(i.position() == 0);
	CHECK(i.get<uint32_t>() == value2);
	CHECK(i.position() == 4);
	CHECK(i.get<uint16_t>() == value1);
	CHECK(i.position() == 6);
	CHECK_THROWS_AS(i.get<uint8_t>(), std::out_of_range);

}

}
