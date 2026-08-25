// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/encrypted_key.hpp>
#include <securepath/crypto/enveloped_content.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/signature.hpp>
#include <securepath/crypto/types.hpp>
#include <securepath/serialisation/util.hpp>

#include "support/test_keys.hpp"

namespace securepath::crypto::test {

TEST_CASE("signature bit flips are detected", "[security][signature]") {
	for(suite s : all_suites()) {
		auto key = generate_private_key(s);
		auto pub = key.public_key();
		octet_vector data = random_octet_vector(64);
		signature sig = key.sign(data);
		REQUIRE(pub.verify(sig, data));

		for(std::size_t i : {std::size_t(0), sig.data().size()/2, sig.data().size()-1}) {
			signature bad(sig.issuer(), flip_bit(sig.data(), i));
			CHECK(!pub.verify(bad, data));
		}
		CHECK(!pub.verify(sig, flip_bit(data, 10)));
		CHECK(!pub.verify(signature(sig.issuer(), octet_vector(sig.data().begin(), sig.data().end()-1)), data));
		CHECK(!pub.verify(signature(sig.issuer(), {}), data));
	}
}

TEST_CASE("ciphertext bit flips are detected", "[security][encryption]") {
	for(suite s : all_suites()) {
		auto key = generate_private_key(s);
		octet_vector data = random_octet_vector(64);
		octet_vector ct = key.public_key().encrypt(data);
		REQUIRE(key.decrypt(ct) == data);

		// every region of the blob: kem ciphertexts, iv, encrypted data, tag
		for(std::size_t i = 8; i < ct.size(); i += 97) {
			CHECK_THROWS_AS(key.decrypt(flip_bit(ct, i)), bad_ciphertext);
		}
		CHECK_THROWS_AS(key.decrypt(flip_bit(ct, ct.size()-1)), bad_ciphertext);
		CHECK_THROWS_AS(key.decrypt(octet_vector(ct.begin(), ct.end()-1)), bad_ciphertext);
		CHECK_THROWS_AS(key.decrypt(octet_vector{}), bad_ciphertext);
		CHECK_THROWS_AS(key.decrypt(random_octet_vector(ct.size())), bad_ciphertext);
	}
}

TEST_CASE("wrong recipient cannot decrypt", "[security][encryption]") {
	auto keys = generate_test_keys(2);
	octet_vector data = random_octet_vector(64);
	octet_vector ct = keys[0].public_key().encrypt(data);
	CHECK_THROWS_AS(keys[1].decrypt(ct), bad_ciphertext);

	encrypted_key ek = encrypt_key(keys[0].public_key(), data);
	CHECK_THROWS_AS(decrypt_key(keys[1], ek), wrong_key);
	// forged id: points at the other key but the ciphertext is not for it
	encrypted_key forged(keys[1].id(), ek.data());
	CHECK_THROWS_AS(decrypt_key(keys[1], forged), bad_ciphertext);
}

TEST_CASE("suite mismatch is rejected", "[security][suite]") {
	auto low = generate_private_key(suite::pq1);
	auto high = generate_private_key(suite::pq1_high);
	octet_vector data = random_octet_vector(32);

	CHECK_THROWS_AS(low.decrypt(high.public_key().encrypt(data)), bad_ciphertext);
	CHECK_THROWS_AS(high.decrypt(low.public_key().encrypt(data)), bad_ciphertext);
	CHECK(!low.public_key().verify(high.sign(data), data));
	CHECK(!high.public_key().verify(low.sign(data), data));
}

TEST_CASE("self signature binds certificate ids and suite", "[security][public_key]") {
	auto key = generate_private_key();
	auto pub = key.public_key();
	octet_vector ser = serialisation::asn_der_serialise(pub);

	// find a byte of the serialised public key that is not the signature and flip it
	bool found_broken = false;
	for(std::size_t i = 12; i < 200 && !found_broken; ++i) {
		try {
			public_key mod = serialisation::asn_der_deserialise<public_key>(flip_bit(ser, i));
			found_broken = !mod.verify_me();
		} catch(std::exception const&) {
			// hit a DER header, that is fine too
		}
	}
	CHECK(found_broken);
}

TEST_CASE("serialised sizes", "[security][sizes]") {
	octet_vector data = random_octet_vector(32);
	auto k1 = generate_private_key(suite::pq1);
	auto k2 = generate_private_key(suite::pq1_high);

	CHECK(k1.sign(data).data().size() == 3309);
	CHECK(k2.sign(data).data().size() == 4627);

	auto size = [](auto const& v) { return serialisation::asn_der_serialise(v).size(); };
	std::size_t pk1 = size(k1.public_key()), pk2 = size(k2.public_key());
	std::size_t sk1 = size(k1), sk2 = size(k2);
	std::size_t ek1 = size(encrypt_key(k1.public_key(), data)), ek2 = size(encrypt_key(k2.public_key(), data));
	std::size_t env1 = size(envelope(k1.public_key(), data)), env2 = size(envelope(k2.public_key(), data));
	INFO("pq1: public_key " << pk1 << " private_key " << sk1 << " encrypted_key " << ek1 << " envelope(1) " << env1);
	INFO("pq1_high: public_key " << pk2 << " private_key " << sk2 << " encrypted_key " << ek2 << " envelope(1) " << env2);

	// protocol limits downstream assume these envelopes (doc/crypto.md)
	CHECK(pk1 > 1952 + 1184 + 32 + 3309);
	CHECK(pk1 < 6700);
	CHECK(ek1 > 32 + 1088 + 12 + 32 + 16);
	CHECK(ek1 < 1300);
	CHECK(pk2 < 9500);
	CHECK(ek2 < 1800);
	CHECK(env1 < ek1 + 100);
}

}
