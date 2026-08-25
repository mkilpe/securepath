// SPDX-License-Identifier: MIT

#include <securepath/common/key_value_cache.hpp>
#include <securepath/common/key_value_database.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/test_frame/test_suite.hpp>

namespace securepath::test {

TEST_CASE("key_value_cache", "[common]") {
	key_value_cache cache;

	CHECK(!cache.find("test"));
	CHECK(!cache.find<int>("test2"));

	cache.insert("test", to_octet_vector("some"));
	cache.insert("test2", 1);

	CHECK(cache.find("test").value_or(octet_vector{}) == to_octet_vector("some"));
	CHECK(cache.find<int>("test2").value_or(0) == 1);
	CHECK_THROWS(cache.find<int>("test"));

	cache.erase("test");
	CHECK(!cache.find("test"));
}

TEST_CASE("key_value_database", "[common]") {
	std::remove("key_value_test.db");
	key_value_database db{database::sqlite::create_sqlite_connection("key_value_test.db"), "test", 1};
	key_value_database db_other{database::sqlite::create_sqlite_connection("key_value_test.db"), "test", 2};

	CHECK(!db.find("test"));
	CHECK(!db.find<int>("test2"));

	db.insert("test", to_octet_vector("some"));
	db.insert("test2", 1);

	CHECK(db.find("test").value_or(octet_vector{}) == to_octet_vector("some"));
	CHECK(db.find<int>("test2").value_or(0) == 1);
	CHECK_THROWS(db.find<int>("test"));

	CHECK(!db_other.find("test"));
	db_other.insert("test", to_octet_vector("ggg"));
	CHECK(db_other.find("test").value_or(octet_vector{}) == to_octet_vector("ggg"));
	CHECK(db.find("test").value_or(octet_vector{}) == to_octet_vector("some"));

	db.erase("test");
	CHECK(!db.find("test"));
}

TEST_CASE("key_value_access", "[common]") {
	std::remove("key_value_test.db");
	key_value_database db{database::sqlite::create_sqlite_connection("key_value_test.db"), "test", 1};
	key_value_cache cache{key_value_access_ptr{&db, [](auto){}}};

	CHECK(!cache.find("test"));

	cache.insert("test", to_octet_vector("some"));
	CHECK(cache.find("test").value_or(octet_vector{}) == to_octet_vector("some"));
	CHECK(db.find("test").value_or(octet_vector{}) == to_octet_vector("some"));

	cache.erase("test");
	CHECK(!cache.find("test"));
	CHECK(!db.find("test"));

	db.insert("hips", 1);
	CHECK(cache.find<int>("hips").value_or(0) == 1);
}

}
