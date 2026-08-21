// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/octet_vector.hpp>

namespace securepath::test {

void check_octet_content(octet_vector const& vec, octet_vector const& o, std::size_t x, std::size_t incr = 0) {

	bool b = vec.size() >= x && o.size() >= x;
	REQUIRE(b);

	for(std::size_t i = 0; i < x; ++i) {
		CHECK(vec[i+incr] == o[i]);
	}

}

TEST_CASE("octet_vector subbuffer", "[octet_vector]") {

	octet_vector vec = securepath::test::random_octet_vector((std::size_t)10);
	octet_vector o1 = subbuffer(vec, vec.size());
	octet_vector o2 = subbuffer(vec, 5);
	octet_vector o3 = subbuffer(vec, 0);
	octet_vector o4 = subbuffer(vec, 5, 1);

	CHECK(o1.size() == 0);
	CHECK(o2.size() == 5);
	CHECK(o3.size() == vec.size());

	check_octet_content(vec, o2, 5, 5);
	check_octet_content(vec, o3, 10);

	CHECK((subbuffer(vec, 5, 0).size() == 0));

	REQUIRE(o4.size() == 1);
	CHECK(o4[0] == vec[5]);

}

TEST_CASE("octet_vector operator+", "[octet_vector]") {
	octet_vector a = to_octet_vector("first");
	octet_vector b = to_octet_vector("second");
	octet_vector c = to_octet_vector("firstsecond");
	CHECK(c == (a+b));
}

TEST_CASE("octet_vector operator^", "[octet_vector]") {
	{
		octet_vector a(10, 0x13);
		octet_vector b(10, 0xaa);
		octet_vector c(10, 0xb9);

		CHECK(c == (a^b));
		CHECK(c == (b^a));
	}
	{
		octet_vector a(10, 0x13);
		octet_vector b(15, 0xaa);
		octet_vector c = octet_vector(10, 0xb9) + octet_vector(5, 0xaa);

		CHECK(c == (a^b));
		CHECK(c == (b^a));
	}
	{
		octet_vector a(15, 0x13);
		octet_vector b(10, 0xaa);
		octet_vector c = octet_vector(10, 0xb9) + octet_vector(5, 0x13);

		CHECK(c == (a^b));
		CHECK(c == (b^a));
	}
}

}
