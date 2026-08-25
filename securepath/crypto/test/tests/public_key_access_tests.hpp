// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_access.hpp>

#include <optional>

namespace securepath::crypto::test {

template<typename Find, typename Remove>
void public_key_access_empty_test(Find find_func, Remove remove_func) {
	auto key = generate_private_key();
	CHECK_NOTHROW(remove_func(key.id()));
	CHECK(find_func(key.id()) == std::nullopt);
}

template<typename Find, typename Insert, typename Remove>
void public_key_find_insert_remove_test_1(Find find_func, Insert insert_func, Remove remove_func) {
	auto key1 = generate_private_key().public_key();
	auto key2 = generate_private_key().public_key();
	auto key3 = generate_private_key().public_key();
	insert_func(key1);
	insert_func(key2);
	auto ret1 = find_func(key1.id());
	auto ret2 = find_func(key2.id());
	auto ret3 = find_func(key3.id());
	REQUIRE(ret1);
	REQUIRE(ret2);
	CHECK(ret3 == std::nullopt);
	CHECK(ret1.value().id() == key1.id());
	CHECK(ret2.value().id() == key2.id());
	CHECK(ret1.value().verify_me());
	remove_func(key1.id());
	CHECK(find_func(key1.id()) == std::nullopt);
	CHECK(find_func(key2.id()) != std::nullopt);
	remove_func(key2.id());
	CHECK(find_func(key1.id()) == std::nullopt);
	CHECK(find_func(key2.id()) == std::nullopt);
}

template<typename Find, typename Insert, typename Remove>
void public_key_access_duplicate_test_1(Find find_func, Insert insert_func, Remove remove_func) {
	auto key1 = generate_private_key().public_key();
	auto key2 = generate_private_key().public_key();
	insert_func(key1);
	insert_func(key1);
	insert_func(key2);
	insert_func(key2);
	REQUIRE(find_func(key1.id()) != std::nullopt);
	REQUIRE(find_func(key2.id()) != std::nullopt);
	remove_func(key1.id());
	remove_func(key2.id());
	CHECK(find_func(key1.id()) == std::nullopt);
	CHECK(find_func(key2.id()) == std::nullopt);
}

}
