// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/certificate_chain.hpp>
#include <securepath/crypto/identifier_certificate.hpp>
#include <securepath/crypto/key_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/root_public_key.hpp>
#include <securepath/crypto/test/support/pki_test_context.hpp>
#include <securepath/crypto/test/support/public_key_test_cache.hpp>
#include <securepath/crypto/test/support/test_keys.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

namespace {

// root -> key1 (ca 1) -> key2 (ca 0) with all keys referencing their certificates
struct three_link_pki {
	three_link_pki(suite s = default_suite(), key_cert_restriction rest1 = {}, key_cert_restriction rest2 = {})
	: root(generate_private_key(s))
	, key1(generate_private_key(s))
	, key2(generate_private_key(s))
	, keys{root.public_key()}
	{
		public_key pkey1 = key1.public_key();
		public_key pkey2 = key2.public_key();
		cert1 = create_key_certificate(root, pkey1, 1, rest1);
		cert2 = create_key_certificate(key1, pkey2, 0, rest2);
		pkey1.add_certificate_id(cert1.id());
		key1.set_public_key(pkey1);
		pkey2.add_certificate_id(cert2.id());
		key2.set_public_key(pkey2);
		certs.insert(cert1);
		certs.insert(cert2);
		keys.insert(key1.public_key());
		keys.insert(key2.public_key());
	}

	private_key root;
	private_key key1;
	private_key key2;
	certificate cert1;
	certificate cert2;
	certificate_cache certs;
	public_key_test_cache keys;
};

}

TEST_CASE("certificate_chain", "[certificate_chain]") {
	three_link_pki pki;
	auto chain = create_certificate_chain(pki.key2.public_key(), pki.keys, pki.certs);
	REQUIRE(chain);
	CHECK(chain->is_valid());
	CHECK(chain->is_authentic(pki.keys, pki.certs));
	CHECK(chain->root_key_id() == pki.root.id());
	CHECK(chain->subject().id() == pki.key2.id());
	CHECK(chain->subject_ca_level() == 0);
	CHECK(std::distance(chain->begin(), chain->end()) == 2);

	//add link test
	auto partial_chain = create_certificate_chain(pki.key1.public_key(), pki.keys, pki.certs);
	REQUIRE(partial_chain);
	CHECK(partial_chain->is_valid());
	CHECK(partial_chain->is_authentic(pki.keys, pki.certs));
	CHECK(partial_chain->subject_ca_level() == 1);
	CHECK_NOTHROW(partial_chain->add_link(pki.key2.public_key(), pki.cert2));
	CHECK(partial_chain->is_valid());
	CHECK(partial_chain->is_authentic(pki.keys, pki.certs));

	//add_link to empty
	certificate_chain empty;
	CHECK(!empty.is_valid());
	CHECK_THROWS(empty.subject());
	CHECK_THROWS(empty.add_link(pki.key1.public_key(), pki.cert1));
	CHECK_NOTHROW(empty.add_link(pki.keys, pki.key1.public_key(), pki.cert1));
	CHECK(empty.is_valid());
	CHECK(empty.is_authentic(pki.keys, pki.certs));
}

TEST_CASE("certificate_chain every suite", "[certificate_chain][suite]") {
	for(suite s : all_suites()) {
		three_link_pki pki(s);
		auto chain = create_certificate_chain(pki.key2.public_key(), pki.keys, pki.certs);
		REQUIRE(chain);
		CHECK(chain->is_authentic(pki.keys, pki.certs));
	}
}

TEST_CASE("certificate_chain serialisation", "[certificate_chain][serialisation]") {
	three_link_pki pki;
	auto chain = create_certificate_chain(pki.key2.public_key(), pki.keys, pki.certs);
	REQUIRE(chain);
	auto ser = serialisation::asn_der_serialise(*chain);
	auto restored = serialisation::asn_der_deserialise<certificate_chain>(ser);
	CHECK(restored.is_valid());
	CHECK(restored.is_authentic(pki.keys, pki.certs));
	CHECK(restored.root_key_id() == chain->root_key_id());
	CHECK(restored.subject().id() == chain->subject().id());
	CHECK(to_string(restored) == to_string(*chain));
}

TEST_CASE("certificate_chain uses the process-wide root key by default", "[certificate_chain][root_public_key]") {
	clear_root_public_key();
	CHECK(!has_root_public_key());
	CHECK_THROWS(root_public_key());
	{
		pki_test_context pki;
		CHECK(has_root_public_key());
		CHECK(root_public_key().id() == pki.root.id());
		public_key_cache keys; // plain cache: find_root_key goes to root_public_key()
		CHECK(pki.ca_chain.is_authentic(keys, pki.certs));
		private_key server = generate_private_key();
		auto chain = pki.chain_for_server_key(server, "host.example.org");
		CHECK(chain.is_authentic(keys, pki.certs));
		CHECK(chain.is_authentic(keys, pki.certs, key_cert_restriction().hostname("host.example.org")));
		CHECK(chain.is_authentic(keys, pki.certs, key_cert_restriction().hostname("sub.host.example.org")));
		CHECK(!chain.is_authentic(keys, pki.certs, key_cert_restriction().hostname("other.example.org")));
		CHECK(chain.subject().id() == server.id());
		// a different root in the cache rejects it
		public_key_test_cache other_root{generate_private_key().public_key()};
		CHECK(!chain.is_authentic(other_root, pki.certs));
	}
	// the test context restored the previous state (none)
	CHECK(!has_root_public_key());
	CHECK_THROWS_AS(set_root_public_key(public_key{}), error);
}

TEST_CASE("certificate_chain invalid chains are rejected", "[certificate_chain][security]") {
	three_link_pki pki;

	SECTION("certificate not signed by the previous key") {
		private_key other = generate_private_key();
		public_key pkey2 = pki.key2.public_key();
		auto bad_cert = create_key_certificate(other, pkey2, 0);
		pkey2.add_certificate_id(bad_cert.id());
		pkey2.sign_me(pki.key2);
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), pki.cert1}, {pkey2, bad_cert}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("subject public key whose self signature is broken") {
		public_key pkey2 = pki.key2.public_key();
		pkey2.add_certificate_id(certificate_id(octet_vector(32, 1))); // changes the content, not re-signed
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), pki.cert1}, {pkey2, pki.cert2}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("wrong certificate type in the chain") {
		auto id_cert = create_identifier_certificate(pki.key1, "not a key cert");
		public_key pkey2 = pki.key2.public_key();
		pkey2.add_certificate_id(id_cert.id());
		pkey2.sign_me(pki.key2);
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), pki.cert1}, {pkey2, id_cert}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("certificate subject does not match the key in the chain") {
		private_key other = generate_private_key();
		public_key pother = other.public_key();
		pother.add_certificate_id(pki.cert2.id());
		pother.sign_me(other);
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), pki.cert1}, {pother, pki.cert2}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("certificate not referenced by the public key") {
		public_key pkey2 = pki.key2.public_key();
		pkey2.remove_certificate_id(pki.cert2.id());
		pkey2.sign_me(pki.key2);
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), pki.cert1}, {pkey2, pki.cert2}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("ca level violation: a ca 0 key certifies another key") {
		private_key key3 = generate_private_key();
		public_key pkey3 = key3.public_key();
		auto cert3 = create_key_certificate(pki.key2, pkey3, 0);
		pkey3.add_certificate_id(cert3.id());
		key3.set_public_key(pkey3);
		auto chain = create_certificate_chain(pki.key2.public_key(), pki.keys, pki.certs);
		REQUIRE(chain);
		CHECK_THROWS(chain->add_link(key3.public_key(), cert3));
		certificate_chain forced{pki.root.id(), {{pki.key1.public_key(), pki.cert1}, {pki.key2.public_key(), pki.cert2}, {key3.public_key(), cert3}}};
		CHECK(!forced.is_authentic(pki.keys, pki.certs));
	}
	SECTION("ca level violation: equal level granted by the root is not enough") {
		private_key key3 = generate_private_key();
		public_key pkey3 = key3.public_key();
		auto cert3 = create_key_certificate(pki.key1, pkey3, 1); // key1 has ca 1, may only grant < 1
		pkey3.add_certificate_id(cert3.id());
		key3.set_public_key(pkey3);
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), pki.cert1}, {key3.public_key(), cert3}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("revoked link (stapled revocation present)") {
		certificate revoked = pki.cert1;
		revoked.set_revocation(revoke_certificate(pki.root, revoked));
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), revoked}, {pki.key2.public_key(), pki.cert2}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
		certificate_cache certs;
		certs.insert(revoked);
		certs.insert(pki.cert2);
		CHECK(!create_certificate_chain(pki.key2.public_key(), pki.keys, certs));
	}
	SECTION("revoked link caught via the store even when the stapled revocation is omitted") {
		// doc/threat_model.md F1: a holder of a revoked certificate omits the revocation from
		// the chain it presents; validation must still reject it by consulting the verifier's
		// own store, which holds the revocation.
		auto chain = create_certificate_chain(pki.key2.public_key(), pki.keys, pki.certs);
		REQUIRE(chain);
		CHECK(chain->is_authentic(pki.keys, pki.certs)); // authentic before revocation

		certificate revoked = pki.cert1; // no stapled revocation on the presented chain
		revoked.set_revocation(revoke_certificate(pki.root, revoked));
		pki.certs.remove(pki.cert1.id());
		pki.certs.insert(revoked); // the store now knows cert1 is revoked

		CHECK(!chain->is_authentic(pki.keys, pki.certs));
	}
	SECTION("a stapled revocation for a different certificate is ignored") {
		// doc/threat_model.md F2: a genuine issuer-signed revocation targeting cert2 is
		// transplanted onto cert1; the cid mismatch means it must be ignored, not treated as
		// revoking cert1, so the chain stays authentic.
		certificate tampered = pki.cert1;
		tampered.set_revocation(revoke_certificate(pki.key1, pki.cert2));
		certificate_chain chain{pki.root.id(), {{pki.key1.public_key(), tampered}, {pki.key2.public_key(), pki.cert2}}};
		CHECK(chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("unknown root") {
		certificate_chain chain{generate_private_key().id(), {{pki.key1.public_key(), pki.cert1}, {pki.key2.public_key(), pki.cert2}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
	SECTION("links in the wrong order") {
		certificate_chain chain{pki.root.id(), {{pki.key2.public_key(), pki.cert2}, {pki.key1.public_key(), pki.cert1}}};
		CHECK(!chain.is_authentic(pki.keys, pki.certs));
	}
}

TEST_CASE("certificate_chain hostname restrictions", "[certificate_chain][security]") {
	three_link_pki pki(default_suite(), key_cert_restriction().hostname("example.org"), key_cert_restriction().hostname("a.example.org"));
	auto chain = create_certificate_chain(pki.key2.public_key(), pki.keys, pki.certs);
	REQUIRE(chain);
	CHECK(chain->is_authentic(pki.keys, pki.certs));
	CHECK(chain->subject_restrictions().hostname() == "a.example.org");
	CHECK(chain->is_authentic(pki.keys, pki.certs, key_cert_restriction().hostname("a.example.org")));
	CHECK(chain->is_authentic(pki.keys, pki.certs, key_cert_restriction().hostname("deep.a.example.org")));
	CHECK(chain->is_authentic(pki.keys, pki.certs, key_cert_restriction().hostname("A.EXAMPLE.ORG")));
	CHECK(!chain->is_authentic(pki.keys, pki.certs, key_cert_restriction().hostname("b.example.org")));
	CHECK(!chain->is_authentic(pki.keys, pki.certs, key_cert_restriction().hostname("example.org")));
	CHECK(!chain->is_authentic(pki.keys, pki.certs, key_cert_restriction().hostname("xa.example.org")));
	CHECK(!chain->is_authentic(pki.keys, pki.certs, key_cert_restriction()));

	// a link that widens the restriction granted by its issuer is not authentic
	three_link_pki wide(default_suite(), key_cert_restriction().hostname("a.example.org"), key_cert_restriction().hostname("example.org"));
	CHECK(!create_certificate_chain(wide.key2.public_key(), wide.keys, wide.certs));
	certificate_chain forced{wide.root.id(), {{wide.key1.public_key(), wide.cert1}, {wide.key2.public_key(), wide.cert2}}};
	CHECK(!forced.is_authentic(wide.keys, wide.certs));
}

}
