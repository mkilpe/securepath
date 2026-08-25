// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include "tools/test_db.hpp"

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/private_data_database.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/test/support/pki_test_context.hpp>
#include <securepath/crypto/test/support/test_keys.hpp>
#include <securepath/util/octet_vector.hpp>

#include <memory>
#include <string>

namespace securepath::crypto::test {

namespace {

struct test_type {
	std::string data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & data;
	}
};

void test_normal_function(private_data_access_ptr access) {
	// private key stuff
	CHECK(!access->my_private_key());
	CHECK_THROWS(my_private_key(*access));
	auto key = generate_private_key();
	access->set_my_private_key(key);
	CHECK(access->my_private_key());
	CHECK(securepath::test::compare_ser(my_private_key(*access), key));
	// the restored key works
	octet_vector const msg = random_octet_vector(20);
	CHECK(key.public_key().verify(my_private_key(*access).sign(msg), msg));
	CHECK(my_private_key(*access).decrypt(key.public_key().encrypt(msg)) == msg);
	// certificate chain stuff
	CHECK(!access->my_certificate_chain());
	access->set_my_certificate_chain(certificate_chain{});
	CHECK(access->my_certificate_chain());
}

void test_meta_function(private_data_access_ptr access) {
	CHECK(!access->find(""));
	CHECK(!access->find("some"));
	{ //untyped insert and find
		access->insert("test", to_octet_vector("data"));
		auto result = access->find("test");
		REQUIRE(result);
		CHECK(*result == to_octet_vector("data"));
	}
	{ //typed insert and find
		access->insert("key", test_type{"other data"});
		CHECK(access->find("key"));
		auto result = access->find<test_type>("key");
		REQUIRE(result);
		CHECK(result->data == "other data");
	}
	{ // replace
		access->insert("key", to_octet_vector("some"));
		auto result = access->find("key");
		REQUIRE(result);
		CHECK(*result == to_octet_vector("some"));
	}
	{ //erase
		access->erase("key");
		CHECK(!access->find("key"));
		CHECK_NOTHROW(access->erase("random")); //no op
	}
	{ //wrong type
		CHECK_THROWS(access->find<test_type>("test"));
	}
}

}

TEST_CASE("private_data_database crypto", "[private_data_database][private_data_access]") {
	scoped_test_db db("private_data_1");
	test_normal_function(std::make_shared<private_data_database>(db.connect()));
}

TEST_CASE("private_data_database metadata", "[private_data_database][private_data_access]") {
	scoped_test_db db("private_data_2");
	test_meta_function(std::make_shared<private_data_database>(db.connect()));
}

TEST_CASE("private_data_cache crypto", "[private_data_cache][private_data_access]") {
	test_normal_function(std::make_shared<private_data_cache>());
}

TEST_CASE("private_data_cache metadata", "[private_data_cache][private_data_access]") {
	test_meta_function(std::make_shared<private_data_cache>());
}

TEST_CASE("private_data_cache with database backend", "[private_data_cache][private_data_access]") {
	scoped_test_db db("private_data_3");
	auto backend = std::make_shared<private_data_database>(db.connect());
	auto key = generate_private_key();
	backend->set_my_private_key(key);
	backend->insert("meta", to_octet_vector("value"));
	private_data_cache cache(backend);
	// read through
	REQUIRE(cache.my_private_key());
	CHECK(cache.my_private_key()->id() == key.id());
	REQUIRE(cache.find("meta"));
	// write through
	cache.insert("other", to_octet_vector("x"));
	CHECK(backend->find("other"));
	cache.erase("meta");
	CHECK(!backend->find("meta"));
}

TEST_CASE("private_data_database keeps a real certificate chain for every suite", "[private_data_database][private_data_access][suite]") {
	for(suite s : all_suites()) {
		pki_test_context pki(s);
		scoped_test_db db("private_data_chain_" + std::string(to_string(s)));
		private_key server = generate_private_key(s);
		auto chain = pki.chain_for_server_key(server, "srv.example.org");
		{
			private_data_database store(db.connect());
			store.set_my_private_key(server);
			store.set_my_certificate_chain(chain);
		}
		private_data_database store(db.connect());
		auto restored_chain = store.my_certificate_chain();
		REQUIRE(restored_chain);
		public_key_cache keys;
		CHECK(restored_chain->is_authentic(keys));
		CHECK(restored_chain->subject().id() == my_private_key(store).id());
	}
}

}
