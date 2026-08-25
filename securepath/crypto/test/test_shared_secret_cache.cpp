// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "tests/shared_secret_access_tests.hpp"
#include "tools/shared_secret_access_functions.hpp"
#include "tools/test_db.hpp"

#include <securepath/crypto/random.hpp>
#include <securepath/crypto/shared_secret_cache.hpp>
#include <securepath/crypto/shared_secret_database.hpp>

namespace securepath::crypto::test {

namespace {

shared_secret_access_ptr cache_with_db_backend(scoped_test_db const& db) {
	shared_secret_access_ptr p = std::make_shared<shared_secret_database>(db.connect());
	return std::make_shared<shared_secret_cache>(p);
}

}

TEST_CASE("shared_secret_cache empty", "[shared_secret_cache][shared_secret_access]") {
	shared_secret_access_ptr access = std::make_shared<shared_secret_cache>();
	shared_secret_empty_test(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache empty with backend", "[shared_secret_cache][shared_secret_access]") {
	scoped_test_db db("shared_cache_1");
	auto access = cache_with_db_backend(db);
	shared_secret_empty_test(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache basic", "[shared_secret_cache][shared_secret_access]") {
	shared_secret_access_ptr access = std::make_shared<shared_secret_cache>();
	shared_secret_find_insert_remove_test_1(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache basic with backend", "[shared_secret_cache][shared_secret_access]") {
	scoped_test_db db("shared_cache_2");
	auto access = cache_with_db_backend(db);
	shared_secret_find_insert_remove_test_1(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache duplicate test", "[shared_secret_cache][shared_secret_access]") {
	shared_secret_access_ptr access = std::make_shared<shared_secret_cache>();
	shared_secret_duplicate_test_1(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache duplicate test with backend", "[shared_secret_cache][shared_secret_access]") {
	scoped_test_db db("shared_cache_3");
	auto access = cache_with_db_backend(db);
	shared_secret_duplicate_test_1(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache empty data", "[shared_secret_cache][shared_secret_access]") {
	shared_secret_access_ptr access = std::make_shared<shared_secret_cache>();
	shared_secret_empty_data_test(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache empty data with backend", "[shared_secret_cache][shared_secret_access]") {
	scoped_test_db db("shared_cache_4");
	auto access = cache_with_db_backend(db);
	shared_secret_empty_data_test(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_cache multiple backends", "[shared_secret_cache][shared_secret_access]") {
	scoped_test_db db1("shared_cache_5a");
	scoped_test_db db2("shared_cache_5b");
	shared_secret_access_ptr backend1 = std::make_shared<shared_secret_database>(db1.connect());
	shared_secret_access_ptr backend2 = std::make_shared<shared_secret_database>(db2.connect());
	octet_vector key1 = random_octet_vector(32);
	octet_vector key2 = random_octet_vector(32);
	octet_vector key3 = random_octet_vector(32);
	octet_vector data1 = random_octet_vector(512);
	octet_vector data2 = random_octet_vector(512);
	octet_vector data3 = random_octet_vector(512);
	backend1->insert(key1, data1);
	backend2->insert(key2, data2);
	shared_secret_cache cache;
	cache.add_backend(backend1);
	cache.add_backend(backend2);
	std::optional<octet_vector> res1 = cache.find(key1);
	std::optional<octet_vector> res2 = cache.find(key2);
	REQUIRE((res1 && res2));
	CHECK(*res1 == data1);
	CHECK(*res2 == data2);
	cache.insert(key3, data3);
	CHECK(backend1->find(key3));
	CHECK(backend2->find(key3));
	cache.remove(key1);
	cache.remove(key2);
	cache.remove(key3);
	CHECK(!cache.find(key1));
	CHECK(!cache.find(key2));
	CHECK(!cache.find(key3));
}

}
