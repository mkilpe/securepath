// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "tests/shared_secret_access_tests.hpp"
#include "tools/shared_secret_access_functions.hpp"
#include "tools/test_db.hpp"

#include <securepath/crypto/shared_secret_database.hpp>

namespace securepath::crypto::test {

TEST_CASE("shared_secret_database empty", "[shared_secret_database][shared_secret_access]") {
	scoped_test_db db("shared_secret_db_1");
	shared_secret_access_ptr access = std::make_shared<shared_secret_database>(db.connect());
	shared_secret_empty_test(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_database basic", "[shared_secret_database][shared_secret_access]") {
	scoped_test_db db("shared_secret_db_2");
	shared_secret_access_ptr access = std::make_shared<shared_secret_database>(db.connect());
	shared_secret_find_insert_remove_test_1(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_database duplicate", "[shared_secret_database][shared_secret_access]") {
	scoped_test_db db("shared_secret_db_3");
	shared_secret_access_ptr access = std::make_shared<shared_secret_database>(db.connect());
	shared_secret_duplicate_test_1(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

TEST_CASE("shared_secret_database empty data", "[shared_secret_database][shared_secret_access]") {
	scoped_test_db db("shared_secret_db_4");
	shared_secret_access_ptr access = std::make_shared<shared_secret_database>(db.connect());
	shared_secret_empty_data_test(shared_secret_find_func(access), shared_secret_insert_func(access), shared_secret_remove_func(access));
}

}
