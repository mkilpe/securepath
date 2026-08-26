// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/identifier_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/property_certificate.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/test/support/test_keys.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

TEST_CASE("certificate basic", "[certificate]") {
	auto key1 = generate_private_key();
	auto key2 = generate_private_key();
	certificate cert;
	cert.sign_me(key1);
	CHECK(cert.type() == 0);
	CHECK(cert.verify_me(key1.public_key()));
	CHECK(!cert.verify_me(key2.public_key()));
	CHECK(cert.is_authentic(key1.public_key()));
	CHECK(!cert.is_authentic(key2.public_key()));
	CHECK(cert.issuer() == key1.id());
}

TEST_CASE("certificate every suite", "[certificate][suite]") {
	for(suite s : all_suites()) {
		auto key = generate_private_key(s);
		certificate cert(0, random_octet_vector(32));
		cert.sign_me(key);
		CHECK(cert.verify_me(key.public_key()));
		CHECK(cert.id().is_valid());
	}
}

TEST_CASE("certificate serialise", "[certificate][serialisation]") {
	auto key = generate_private_key();
	octet_vector o = random_octet_vector(32);
	certificate cert(0, o);
	cert.sign_me(key);
	auto ser = serialisation::asn_der_serialise(cert);
	certificate cert2 = serialisation::asn_der_deserialise<certificate>(ser);
	CHECK(cert2.verify_me(key.public_key()));
	CHECK(cert2.is_authentic(key.public_key()));
	CHECK(cert2.id() == cert.id());
	CHECK(cert2 == cert);
}

TEST_CASE("certificate duplicate certificate", "[certificate]") {
	auto key = generate_private_key();
	octet_vector o = random_octet_vector(32);
	certificate cert1(0, o);
	certificate cert2(0, o);
	cert1.sign_me(key);
	cert2.sign_me(key);
	// ML-DSA signing is randomised, so the same content signed twice gives different ids
	CHECK(cert1.id() != cert2.id());
	CHECK(cert1 != cert2);
}

// mirrors the serialised layout of certificate without the revocation and trailing data
struct cert_alter_test_type {
	int version{};
	int certificate_type{};
	octet_vector certificate_data;
	signature sig;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version & certificate_type & certificate_data & sig;
	}
};

// the exact octets a certificate signs (see certificate::make_sig_data)
struct cert_sig_data_type {
	int version{1};
	int certificate_type{};
	octet_vector certificate_data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version & certificate_type & certificate_data;
	}
};

TEST_CASE("certificate alter", "[certificate][security]") {
	auto key = generate_private_key();
	octet_vector o = random_octet_vector(32);
	certificate cert1(0, o);
	cert1.sign_me(key);
	CHECK(cert1.verify_me(key.public_key()));
	//use helper type to alter the certificate data
	auto data = serialisation::asn_der_serialise(cert1);
	auto helper = serialisation::asn_der_deserialise<cert_alter_test_type>(data);
	helper.certificate_data[helper.certificate_data.size()/2] ^= 0x1;
	data = serialisation::asn_der_serialise(helper);
	auto cert2 = serialisation::asn_der_deserialise<certificate>(data);
	CHECK(!cert2.verify_me(key.public_key()));
	CHECK(!cert2.is_authentic(key.public_key()));

	// tampered type
	helper = serialisation::asn_der_deserialise<cert_alter_test_type>(serialisation::asn_der_serialise(cert1));
	helper.certificate_type = 5;
	auto cert3 = serialisation::asn_der_deserialise<certificate>(serialisation::asn_der_serialise(helper));
	CHECK(!cert3.verify_me(key.public_key()));

	// tampered signature
	helper = serialisation::asn_der_deserialise<cert_alter_test_type>(serialisation::asn_der_serialise(cert1));
	helper.sig = signature(helper.sig.issuer(), flip_bit(helper.sig.data(), 100));
	auto cert4 = serialisation::asn_der_deserialise<certificate>(serialisation::asn_der_serialise(helper));
	CHECK(!cert4.verify_me(key.public_key()));
}

TEST_CASE("certificate signed under the wrong context is rejected", "[certificate][security]") {
	auto key = generate_private_key();
	octet_vector o = random_octet_vector(32);
	certificate cert(0, o);
	cert.sign_me(key);
	octet_vector const sig_data = serialisation::asn_der_serialise(cert_sig_data_type{1, 0, o});

	auto with_signature = [&](signature sig) {
		auto helper = serialisation::asn_der_deserialise<cert_alter_test_type>(serialisation::asn_der_serialise(cert));
		helper.sig = std::move(sig);
		return serialisation::asn_der_deserialise<certificate>(serialisation::asn_der_serialise(helper));
	};
	// sanity: re-signing the reconstructed data under the right context still verifies
	CHECK(with_signature(key.sign(sig_data, "sp-cert")).verify_me(key.public_key()));
	// application-data signature and other contexts over the same octets must not be accepted as a certificate
	CHECK(!with_signature(key.sign(sig_data)).verify_me(key.public_key()));
	CHECK(!with_signature(key.sign(sig_data, "sp-revocation")).verify_me(key.public_key()));
	CHECK(!with_signature(key.sign(sig_data, "sp-key")).verify_me(key.public_key()));
}

TEST_CASE("certificate extract cert", "[certificate][identifier_certificate_data]") {
	auto key = generate_private_key();
	identifier_certificate_data i("hop");
	octet_vector o = serialisation::asn_der_serialise(i);
	certificate cert(identifier_certificate_data::id, o);
	cert.sign_me(key);
	certificate_id id1 = cert.id();
	auto res = cert.extract<identifier_certificate_data>();
	certificate_id id2 = cert.id();
	CHECK(res.identifier() == i.identifier());
	CHECK(id1 == id2);
	CHECK_THROWS_AS(cert.extract<property_certificate_data>(), invalid_cert_type);
}

TEST_CASE("certificate revoke", "[certificate][revocation]") {
	auto key1 = generate_private_key();
	auto key2 = generate_private_key();
	certificate cert;
	cert.sign_me(key1);
	certificate cert_copy = cert;
	CHECK(cert.is_authentic(key1.public_key()));
	CHECK_THROWS(revoke_certificate(key2, cert));
	auto rev = revoke_certificate(key1, cert);
	CHECK(rev.verify_me(key1.public_key()));
	CHECK(!rev.verify_me(key2.public_key()));
	CHECK(rev.issuer() == key1.id());
	CHECK(rev.id() == cert.id());
	cert.set_revocation(rev);
	CHECK(cert.id() == cert_copy.id());
	CHECK(cert == cert_copy);
	CHECK(cert.revocation());
	CHECK(!cert.is_authentic(key1.public_key()));
	CHECK(cert.verify_me(key1.public_key()));

	// revocation survives serialisation
	auto restored = serialisation::asn_der_deserialise<certificate>(serialisation::asn_der_serialise(cert));
	CHECK(restored.revocation());
	CHECK(!restored.is_authentic(key1.public_key()));
	CHECK(restored.verify_me(key1.public_key()));
}

TEST_CASE("certificate ignores a forged or mismatched stapled revocation", "[certificate][revocation][security]") {
	auto key1 = generate_private_key();
	auto key2 = generate_private_key();

	// (a) a revocation forged by a non-issuer key must be ignored, not treated as revoking
	// the certificate (otherwise an attacker could invalidate any certificate by stapling a
	// bogus revocation onto it -- doc/threat_model.md F2)
	certificate cert;
	cert.sign_me(key1);
	certificate_revocation forged(cert.id());
	forged.sign_me(key2);
	cert.set_revocation(forged);
	CHECK(cert.verify_me(key1.public_key()));     // the certificate's own signature is untouched
	CHECK(!cert.is_revoked(key1.public_key()));    // the forged revocation does not count
	CHECK(cert.is_authentic(key1.public_key()));   // so the certificate is still authentic

	// (b) a genuine issuer-signed revocation, but targeting a different certificate id,
	// transplanted onto this certificate is likewise ignored
	certificate other;
	other.sign_me(key1);
	certificate_revocation mismatched = revoke_certificate(key1, other); // targets other.id()
	certificate cert2;
	cert2.sign_me(key1);
	cert2.set_revocation(mismatched);
	CHECK(!cert2.is_revoked(key1.public_key()));
	CHECK(cert2.is_authentic(key1.public_key()));

	// control: the correct matching issuer-signed revocation DOES revoke
	certificate cert3;
	cert3.sign_me(key1);
	cert3.set_revocation(revoke_certificate(key1, cert3));
	CHECK(cert3.is_revoked(key1.public_key()));
	CHECK(!cert3.is_authentic(key1.public_key()));
}

}
