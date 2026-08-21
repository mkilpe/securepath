// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <securepath/serialisation/octet_vector_stream.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::serialisation::test {

template<typename T>
octet_vector serialise_content(T& t) {
	octet_vector vec;
	octet_vector_stream o_stream(vec);
	asn_der_serialise(o_stream, t);
	return vec;
}

template<typename T>
T deserialise_content(octet_vector& o) {
	octet_vector_stream o_stream(o);
	return asn_der_deserialise<T>(o_stream);
}

TEST_CASE("octet_vector_stream serialisation", "[octet_vector_stream]") {

	std::string s1 = "QWERTYUIOP";
	std::string s2 = "QWERT YUIOP";
	
	octet_vector o1 = securepath::test::random_octet_vector((std::size_t)256);
	octet_vector o2 = securepath::test::random_octet_vector((std::size_t)256);
	octet_vector o3(o2);

	REQUIRE(o1 != o2);
	REQUIRE(o2 == o3);

	octet_vector ser_s1 = serialise_content(s1);
	octet_vector ser_s2 = serialise_content(s2);
	octet_vector ser_o1 = serialise_content(o1);
	octet_vector ser_o2 = serialise_content(o2);
	octet_vector ser_o3 = serialise_content(o3);

	CHECK(ser_o1 != ser_o2);
	CHECK(ser_s1 != ser_s2);
	CHECK(ser_o2 == ser_o3);

	std::string res_s1 = deserialise_content<std::string>(ser_s1);
	std::string res_s2 = deserialise_content<std::string>(ser_s2);
	octet_vector res_o1 = deserialise_content<octet_vector>(ser_o1);
	octet_vector res_o2 = deserialise_content<octet_vector>(ser_o2);
	octet_vector res_o3 = deserialise_content<octet_vector>(ser_o3);

	CHECK(res_s1 == s1);
	CHECK(res_s2 == s2);
	CHECK(res_o1 == o1);
	CHECK(res_o2 == o2);
	CHECK(res_o2 == res_o3);

}

TEST_CASE("octet_vector_stream write read", "[octet_vector_stream]") {

	octet_vector vec = securepath::test::random_octet_vector((std::size_t)10);
	octet_vector copy_vec(vec);

	std::string s1 = "ABC";
	std::string s2 = "EFGH";

	std::vector<char> buf1(vec.size() + s1.size());
	std::vector<char> buf2(s2.size());

	octet_vector_stream o_stream(copy_vec);

	REQUIRE(o_stream.write(s1.c_str(), s1.size()));
	REQUIRE(o_stream.read(buf1.data(), buf1.size()));
	REQUIRE(o_stream.write(s2.c_str(), s2.size()));
	REQUIRE(o_stream.read(buf2.data(), buf2.size()));

	std::string exp1 = std::string(vec.begin(), vec.end()) + s1;
	std::string res1(buf1.begin(), buf1.end());
	std::string res2(buf2.begin(), buf2.end());

	CHECK(exp1 == res1);
	CHECK(s2 == res2);

}

TEST_CASE("octet_vector_stream write read 2", "[octet_vector_stream]") {

	octet_vector vec;
	octet_vector_stream o_stream(vec);
	
	std::string s1 = "1234";
	std::string s2 = "567";

	REQUIRE(o_stream.write(s1.c_str(), s1.size()));
	CHECK(std::string(vec.begin(), vec.end()) == s1);

	REQUIRE(o_stream.write(s2.c_str(), s2.size()));	
	CHECK(std::string(vec.begin(), vec.end()) == s1+s2);

	std::vector<char> buf(s2.size());
	REQUIRE(o_stream.read(buf.data(), s2.size()));

	CHECK(std::string(vec.begin(), vec.end()) == s1+s2);
	CHECK(std::string(buf.begin(), buf.end()) == "123");

	std::vector<char> big_buf(2*s1.size() + 2*s2.size());
	CHECK(!o_stream.read(big_buf.data(), big_buf.size()));

}

TEST_CASE("octet_vector_ostream write past the end grows the vector", "[octet_vector_stream]") {
	// a write position beyond the current size used to underflow the
	// remaining-space computation and resize to a huge value
	octet_vector vec(2);
	octet_vector_ostream out(vec, 10);
	char const payload[] = {1, 2, 3};
	CHECK(out.write(payload, sizeof(payload)));
	CHECK(vec.size() == 13);
	CHECK(vec[10] == 1);
	CHECK(vec[12] == 3);
}

}
