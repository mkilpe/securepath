// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "tests/public_key_access_tests.hpp"
#include "tools/public_key_access_functions.hpp"
#include "tools/test_db.hpp"

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_database.hpp>
#include <securepath/crypto/test/support/test_keys.hpp>

#include <memory>

namespace securepath::crypto::test {

TEST_CASE("public_key_database empty", "[public_key_database][public_key_access]") {
	scoped_test_db db("public_key_db_1");
	public_key_access_ptr access = std::make_shared<public_key_database>(db.connect());
	public_key_access_empty_test(public_key_access_find_func(access), public_key_access_remove_func(access));
}

TEST_CASE("public_key_database basic", "[public_key_database][public_key_access]") {
	scoped_test_db db("public_key_db_2");
	public_key_access_ptr access = std::make_shared<public_key_database>(db.connect());
	public_key_find_insert_remove_test_1(public_key_access_find_func(access), public_key_access_insert_func(access), public_key_access_remove_func(access));
}

TEST_CASE("public_key_database duplicated key", "[public_key_database][public_key_access]") {
	scoped_test_db db("public_key_db_3");
	public_key_access_ptr access = std::make_shared<public_key_database>(db.connect());
	public_key_access_duplicate_test_1(public_key_access_find_func(access), public_key_access_insert_func(access), public_key_access_remove_func(access));
}

TEST_CASE("public_key_database persists every suite across connections", "[public_key_database][public_key_access][suite]") {
	scoped_test_db db("public_key_db_4");
	std::vector<private_key> keys;
	{
		public_key_database store(db.connect());
		for(suite s : all_suites()) {
			keys.push_back(generate_private_key(s));
			store.insert(keys.back().public_key());
		}
	}
	public_key_database store(db.connect());
	for(auto const& key : keys) {
		auto found = store.find(key.id());
		REQUIRE(found);
		CHECK(found->suite() == key.suite());
		CHECK(found->verify_me());
		octet_vector const msg(10, 7);
		CHECK(found->verify(key.sign(msg), msg));
	}
}

}
