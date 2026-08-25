// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include "tests/certificate_tests.hpp"
#include "tools/certificate_access_functions.hpp"
#include "tools/test_db.hpp"

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/certificate_database.hpp>
#include <securepath/crypto/identifier_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/test/support/test_keys.hpp>

namespace securepath::crypto::test {

TEST_CASE("certificate_database empty", "[certificate_database][certificate_access]") {
	scoped_test_db db("cert_db_1");
	certificate_access_ptr access = std::make_shared<certificate_database>(db.connect());
	certificate_access_empty_test(access_find_func(access), access_remove_func(access), access_search_func(access));
}

TEST_CASE("certificate_database basic", "[certificate_database][certificate_access]") {
	scoped_test_db db("cert_db_2");
	certificate_access_ptr access = std::make_shared<certificate_database>(db.connect());
	certificate_access_find_insert_remove_test_1(access_find_func(access), access_insert_func(access), access_remove_func(access));
}

TEST_CASE("certificate_database search_identifier", "[certificate_database][certificate_access]") {
	scoped_test_db db("cert_db_3");
	certificate_access_ptr access = std::make_shared<certificate_database>(db.connect());
	certificate_access_search_identifier_test_1(access_find_func(access), access_insert_func(access), access_remove_func(access), access_search_func(access));
}

TEST_CASE("certificate_database duplicate test", "[certificate_database][certificate_access]") {
	scoped_test_db db("cert_db_4");
	certificate_access_ptr access = std::make_shared<certificate_database>(db.connect());
	certificate_access_duplicate_test_1(access_find_func(access), access_insert_func(access), access_remove_func(access), access_search_func(access));
}

TEST_CASE("certificate_database revocation", "[certificate_database][certificate_access]") {
	scoped_test_db tdb("cert_db_5");
	certificate_database db(tdb.connect());
	auto key = generate_private_key();
	certificate cert;
	cert.sign_me(key);
	certificate cert_copy = cert;
	db.insert(cert);
	CHECK(db.find(cert.id()));
	cert.set_revocation(revoke_certificate(key, cert));
	CHECK_NOTHROW(db.insert(cert));
	CHECK(db.find(cert.id()));
	CHECK_THROWS(db.insert(cert));
	CHECK_THROWS(db.insert(cert_copy));
	certificate rev_cert;
	rev_cert.sign_me(key);
	rev_cert.set_revocation(revoke_certificate(key, rev_cert));
	CHECK_NOTHROW(db.insert(rev_cert));
	CHECK(db.find(rev_cert.id()));
	CHECK_THROWS(db.insert(rev_cert));
}

TEST_CASE("certificate_database persists across connections for every suite", "[certificate_database][certificate_access][suite]") {
	scoped_test_db tdb("cert_db_6");
	std::vector<certificate> certs;
	std::vector<private_key> keys;
	for(suite s : all_suites()) {
		keys.push_back(generate_private_key(s));
		certs.push_back(create_identifier_certificate(keys.back(), "persist"));
	}
	{
		certificate_database db(tdb.connect());
		for(auto const& c : certs) {
			db.insert(c);
		}
	}
	certificate_database db(tdb.connect());
	for(std::size_t i = 0; i != certs.size(); ++i) {
		auto found = db.find(certs[i].id());
		REQUIRE(found);
		CHECK(found->is_authentic(keys[i].public_key()));
	}
	CHECK(db.search_identifier("persist").size() == certs.size());
}

}
