// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "tests/certificate_tests.hpp"
#include "tools/certificate_access_functions.hpp"
#include "tools/test_db.hpp"

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/certificate_database.hpp>
#include <securepath/crypto/key_generation.hpp>

namespace securepath::crypto::test {

namespace {

certificate_access_ptr cache_with_db_backend(scoped_test_db const& db) {
	certificate_access_ptr p = std::make_shared<certificate_database>(db.connect());
	return std::make_shared<certificate_cache>(p);
}

}

TEST_CASE("certificate_cache empty", "[certificate_cache][certificate_access]") {
	certificate_access_ptr access = std::make_shared<certificate_cache>();
	certificate_access_empty_test(access_find_func(access), access_remove_func(access), access_search_func(access));
}

TEST_CASE("certificate_cache empty with backend", "[certificate_cache][certificate_access]") {
	scoped_test_db db("cert_cache_1");
	auto access = cache_with_db_backend(db);
	certificate_access_empty_test(access_find_func(access), access_remove_func(access), access_search_func(access));
}

TEST_CASE("certificate_cache basic", "[certificate_cache][certificate_access]") {
	certificate_access_ptr access = std::make_shared<certificate_cache>();
	certificate_access_find_insert_remove_test_1(access_find_func(access), access_insert_func(access), access_remove_func(access));
}

TEST_CASE("certificate_cache basic with backend", "[certificate_cache][certificate_access]") {
	scoped_test_db db("cert_cache_2");
	auto access = cache_with_db_backend(db);
	certificate_access_find_insert_remove_test_1(access_find_func(access), access_insert_func(access), access_remove_func(access));
}

TEST_CASE("certificate_cache search_identifier with backend", "[certificate_cache][certificate_access]") {
	scoped_test_db db("cert_cache_3");
	auto access = cache_with_db_backend(db);
	certificate_access_search_identifier_test_1(access_find_func(access), access_insert_func(access), access_remove_func(access), access_search_func(access));
}

TEST_CASE("certificate_cache duplicate test", "[certificate_cache][certificate_access]") {
	scoped_test_db db("cert_cache_4");
	auto access = cache_with_db_backend(db);
	certificate_access_duplicate_test_1(access_find_func(access), access_insert_func(access), access_remove_func(access), access_search_func(access));
}

TEST_CASE("certificate_cache with backend", "[certificate_cache][certificate_access]") {
	scoped_test_db db1("cert_cache_5a");
	scoped_test_db db2("cert_cache_5b");
	certificate_cache cache;
	auto key1 = generate_private_key();
	auto key2 = generate_private_key();
	certificate cert1;
	cert1.sign_me(key1);
	certificate cert2;
	cert2.sign_me(key2);
	certificate cert3;
	cert3.sign_me(key1);
	certificate_access_ptr p1 = std::make_shared<certificate_database>(db1.connect());
	certificate_access_ptr p2 = std::make_shared<certificate_database>(db2.connect());
	p1->insert(cert1);
	auto ret1 = cache.find(cert1.id());
	CHECK(ret1 == std::nullopt);
	cache.add_backend(p1);
	auto ret2 = cache.find(cert1.id());
	REQUIRE(ret2);
	CHECK(ret2.value().verify_me(key1.public_key()));
	auto ret3 = cache.find(cert1.id());
	CHECK(ret3.value().verify_me(key1.public_key()));
	p2->insert(cert2);
	cache.insert(cert3);
	cache.add_backend(p2);
	auto ret4 = cache.find(cert2.id());
	auto ret5 = cache.find(cert3.id());
	REQUIRE(ret4);
	REQUIRE(ret5);
	CHECK(ret4.value().verify_me(key2.public_key()));
	CHECK(ret5.value().verify_me(key1.public_key()));
	CHECK(p1->find(cert3.id()));
}

TEST_CASE("certificate_cache revocation", "[certificate_cache][certificate_access]") {
	certificate_cache cache;
	auto key = generate_private_key();
	certificate cert;
	cert.sign_me(key);
	certificate cert_copy = cert;
	cache.insert(cert);
	CHECK(cache.find(cert.id()));
	cert.set_revocation(revoke_certificate(key, cert));
	CHECK_NOTHROW(cache.insert(cert));
	CHECK(cache.find(cert.id()));
	CHECK_THROWS(cache.insert(cert));
	CHECK_THROWS(cache.insert(cert_copy));
	certificate rev_cert;
	rev_cert.sign_me(key);
	rev_cert.set_revocation(revoke_certificate(key, rev_cert));
	CHECK_NOTHROW(cache.insert(rev_cert));
	CHECK(cache.find(rev_cert.id()));
	CHECK_THROWS(cache.insert(rev_cert));
}

}
