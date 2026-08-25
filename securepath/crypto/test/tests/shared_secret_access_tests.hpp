// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/random.hpp>
#include <securepath/crypto/shared_secret_access.hpp>

#include <optional>

namespace securepath::crypto::test {

template<typename Find, typename Insert, typename Remove>
void shared_secret_empty_test(Find find_func, Insert insert_func, Remove remove_func) {
	octet_vector o = random_octet_vector(32);
	octet_span s(o.data(), o.size());
	CHECK_NOTHROW(find_func(s));
	CHECK_NOTHROW(remove_func(s));
	octet_vector empty = {};
	octet_span empty_s(empty.data(), empty.size());
	CHECK_THROWS_AS(insert_func(empty_s, s), invalid_secret_key_size);
}

template<typename Find, typename Insert, typename Remove>
void shared_secret_find_insert_remove_test_1(Find find_func, Insert insert_func, Remove remove_func) {
	octet_vector key1_o = random_octet_vector(32);
	octet_span key1(key1_o.data(), key1_o.size());
	octet_vector key2_o = random_octet_vector(32);
	octet_span key2(key2_o.data(), key2_o.size());
	octet_vector key3_o = random_octet_vector(32);
	octet_span key3(key3_o.data(), key3_o.size());
	octet_vector data1_o = random_octet_vector(512);
	octet_span data1(data1_o.data(), data1_o.size());
	octet_vector data2_o = random_octet_vector(512);
	octet_span data2(data2_o.data(), data2_o.size());
	REQUIRE(!find_func(key1));
	REQUIRE(!find_func(key2));
	REQUIRE(!find_func(key3));
	insert_func(key1, data1);
	std::optional<octet_vector> res1 = find_func(key1);
	std::optional<octet_vector> res2 = find_func(key2);
	CHECK(!res2);
	REQUIRE(res1);
	CHECK(*res1 == data1_o);
	insert_func(key2, data2);
	insert_func(key3, data2);
	res1 = find_func(key1);
	res2 = find_func(key2);
	std::optional<octet_vector> res3 = find_func(key3);
	REQUIRE((res1 && res2 && res3));
	CHECK(*res1 == data1_o);
	CHECK(*res2 == data2_o);
	CHECK(*res3 == data2_o);
	remove_func(key2);
	CHECK(find_func(key1));
	CHECK(!find_func(key2));
	CHECK(find_func(key3));
	remove_func(key1);
	remove_func(key3);
	CHECK(!find_func(key1));
	CHECK(!find_func(key2));
	CHECK(!find_func(key3));
}

template<typename Find, typename Insert, typename Remove>
void shared_secret_duplicate_test_1(Find find_func, Insert insert_func, Remove remove_func) {
	octet_vector key_o = random_octet_vector(32);
	octet_span key(key_o.data(), key_o.size());
	octet_vector data1_o = random_octet_vector(512);
	octet_span data1(data1_o.data(), data1_o.size());
	octet_vector data2_o = random_octet_vector(512);
	octet_span data2(data2_o.data(), data2_o.size());
	REQUIRE(data1_o != data2_o);
	REQUIRE(!find_func(key));
	insert_func(key, data1);
	std::optional<octet_vector> res = find_func(key);
	REQUIRE(res);
	CHECK(*res == data1_o);
	insert_func(key, data2);
	res = find_func(key);
	REQUIRE(res);
	CHECK(*res == data2_o);
	remove_func(key);
	CHECK(!find_func(key));
}

template<typename Find, typename Insert, typename Remove>
void shared_secret_empty_data_test(Find find_func, Insert insert_func, Remove remove_func) {
	octet_vector key_o = random_octet_vector(32);
	octet_span key(key_o.data(), key_o.size());
	octet_vector data1_o = random_octet_vector(512);
	octet_span data1(data1_o.data(), data1_o.size());
	octet_vector empty_o = {};
	octet_span empty(empty_o.data(), empty_o.size());
	REQUIRE_NOTHROW(insert_func(key, empty));
	std::optional<octet_vector> res;
	REQUIRE_NOTHROW(res = find_func(key));
	insert_func(key, data1);
	insert_func(key, empty);
	res = find_func(key);
	REQUIRE(res != std::nullopt);
	CHECK(*res == empty_o);
	remove_func(key);
	CHECK(!find_func(key));
}

}
