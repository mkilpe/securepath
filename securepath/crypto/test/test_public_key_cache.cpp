// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "tests/public_key_access_tests.hpp"
#include "tools/public_key_access_functions.hpp"

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <memory>

namespace securepath::crypto::test {

TEST_CASE("cache empty test", "[public_key_cache][public_key_access]") {
	public_key_access_ptr access = std::make_shared<public_key_cache>();
	public_key_access_empty_test(public_key_access_find_func(access), public_key_access_remove_func(access));
}

TEST_CASE("cache empty with backend", "[public_key_cache][public_key_access]") {
	public_key_access_ptr cache2 = std::make_shared<public_key_cache>();
	public_key_access_ptr access = std::make_shared<public_key_cache>(cache2);
	public_key_access_empty_test(public_key_access_find_func(access), public_key_access_remove_func(access));
}

TEST_CASE("cache basic test", "[public_key_cache][public_key_access]") {
	public_key_access_ptr access = std::make_shared<public_key_cache>();
	public_key_find_insert_remove_test_1(public_key_access_find_func(access), public_key_access_insert_func(access), public_key_access_remove_func(access));
}

TEST_CASE("cache basic with backend", "[public_key_cache][public_key_access]") {
	public_key_access_ptr cache2 = std::make_shared<public_key_cache>();
	public_key_access_ptr access = std::make_shared<public_key_cache>(cache2);
	public_key_find_insert_remove_test_1(public_key_access_find_func(access), public_key_access_insert_func(access), public_key_access_remove_func(access));
}

TEST_CASE("cache duplicated key", "[public_key_cache][public_key_access]") {
	public_key_access_ptr access = std::make_shared<public_key_cache>();
	public_key_access_duplicate_test_1(public_key_access_find_func(access), public_key_access_insert_func(access), public_key_access_remove_func(access));
}

TEST_CASE("cache duplicated key with backend", "[public_key_cache][public_key_access]") {
	public_key_access_ptr cache2 = std::make_shared<public_key_cache>();
	public_key_access_ptr access = std::make_shared<public_key_cache>(cache2);
	public_key_access_duplicate_test_1(public_key_access_find_func(access), public_key_access_insert_func(access), public_key_access_remove_func(access));
}

TEST_CASE("cache search from backend", "[public_key_cache][public_key_access]") {
	public_key_cache cache;
	public_key_access_ptr cache2 = std::make_shared<public_key_cache>();
	auto const key1 = generate_private_key();
	auto const key2 = generate_private_key();
	cache.insert(key1.public_key());
	cache2->insert(key2.public_key());
	auto ret = cache.find(key2.id());
	CHECK(ret == std::nullopt);
	cache.add_backend(cache2);
	ret = cache.find(key2.id());
	REQUIRE(ret != std::nullopt);
	CHECK(key2.id() == ret.value().id());
}

TEST_CASE("cache remove with backend", "[public_key_cache][public_key_access]") {
	public_key_cache cache;
	public_key_access_ptr cache2 = std::make_shared<public_key_cache>();
	auto const key1 = generate_private_key();
	auto const key2 = generate_private_key();
	cache.insert(key1.public_key());
	cache2->insert(key2.public_key());
	cache.add_backend(cache2);
	REQUIRE(cache.find(key1.id()));
	REQUIRE(cache.find(key2.id()));
	cache.remove(key1.id());
	cache.remove(key2.id());
	CHECK(!cache.find(key1.id()));
	CHECK(!cache.find(key2.id()));
	CHECK(!cache2->find(key2.id()));
}

}
