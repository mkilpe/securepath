// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/detail/framing.hpp>
#include <securepath/crypto/detail/hybrid_kem.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/types.hpp>
#include <securepath/util/conversions.hpp>

#include "support/test_keys.hpp"

namespace securepath::crypto::test {

namespace {

octet_vector to_octets(Botan::secure_vector<std::uint8_t> const& v) {
	return octet_vector(v.begin(), v.end());
}

}

TEST_CASE("hybrid kem round trip", "[kem]") {
	for(suite s : all_suites()) {
		auto sk = detail::generate_kem_private_key(s);
		auto pk = detail::kem_public_part(sk);
		CHECK(pk.id == s);

		auto enc = detail::kem_encapsulate(pk);
		CHECK(enc.key.size() == detail::kem_key_size);
		auto key = detail::kem_decapsulate(sk, enc.ct_x, enc.ct_pq);
		CHECK(key == enc.key);

		// second encapsulation is independent
		auto enc2 = detail::kem_encapsulate(pk);
		CHECK(enc2.key != enc.key);
		CHECK(enc2.ct_pq != enc.ct_pq);
	}
}

TEST_CASE("hybrid kem sizes", "[kem]") {
	auto sk1 = detail::generate_kem_private_key(suite::pq1);
	auto pk1 = detail::kem_public_part(sk1);
	auto enc1 = detail::kem_encapsulate(pk1);
	CHECK(pk1.x_pk.size() == 32);
	CHECK(pk1.pq_pk.size() == 1184);
	CHECK(enc1.ct_x.size() == 32);
	CHECK(enc1.ct_pq.size() == 1088);
	CHECK(sk1.x_sk.size() == 32);
	CHECK(sk1.pq_seed.size() == 64);

	auto sk2 = detail::generate_kem_private_key(suite::pq1_high);
	auto pk2 = detail::kem_public_part(sk2);
	auto enc2 = detail::kem_encapsulate(pk2);
	CHECK(pk2.x_pk.size() == 56);
	CHECK(pk2.pq_pk.size() == 1568);
	CHECK(enc2.ct_x.size() == 56);
	CHECK(enc2.ct_pq.size() == 1568);
}

TEST_CASE("hybrid kem tampering", "[kem][security]") {
	for(suite s : all_suites()) {
		auto sk = detail::generate_kem_private_key(s);
		auto pk = detail::kem_public_part(sk);
		auto enc = detail::kem_encapsulate(pk);

		// ML-KEM implicit rejection: a different (not an error) key comes out
		CHECK(detail::kem_decapsulate(sk, enc.ct_x, flip_bit(enc.ct_pq, 100)) != enc.key);
		CHECK(detail::kem_decapsulate(sk, flip_bit(enc.ct_x, 3), enc.ct_pq) != enc.key);
		// wrong sizes are rejected outright
		CHECK_THROWS_AS(detail::kem_decapsulate(sk, enc.ct_x, octet_vector(enc.ct_pq.begin(), enc.ct_pq.end()-1)), bad_ciphertext);
		CHECK_THROWS_AS(detail::kem_decapsulate(sk, octet_vector{}, enc.ct_pq), bad_ciphertext);
		// another key pair does not get the secret
		auto other = detail::generate_kem_private_key(s);
		CHECK(detail::kem_decapsulate(other, enc.ct_x, enc.ct_pq) != enc.key);
		// keys of the wrong suite are rejected
		detail::kem_public_key bad = pk;
		bad.id = s == suite::pq1 ? suite::pq1_high : suite::pq1;
		CHECK_THROWS_AS(detail::kem_encapsulate(bad), invalid_key);
	}
}

TEST_CASE("hybrid kem combiner known answer", "[kem][kat]") {
	// pins the combiner input order and info string (HKDF-SHA3-256 over ss_pq || ss_x || ct_x || pk_x)
	octet_vector const ss_pq(32, 0x01);
	{
		octet_vector const ss_x(32, 0x02), ct_x(32, 0x03), pk_x(32, 0x04);
		auto key = detail::combine_shared_secrets(suite::pq1, ss_pq, ss_x, ct_x, pk_x);
		CHECK(to_hex(to_octets(key)) == "0B67FA6A72B99A4469915EDDC5758C2AF068B249BFD37977F6B6A960A36BA4AA");
	}
	{
		octet_vector const ss_x(56, 0x02), ct_x(56, 0x03), pk_x(56, 0x04);
		auto key = detail::combine_shared_secrets(suite::pq1_high, ss_pq, ss_x, ct_x, pk_x);
		CHECK(to_hex(to_octets(key)) == "926E2EBC170B1B7DF4BCF4B4D9E6C42C3D3337039E48563C627F76016F26E59F");
	}
}

TEST_CASE("signature framing known answer", "[signature][kat]") {
	octet_vector const msg = {'m', 's', 'g'};
	octet_vector framed = detail::frame_message("ctx", msg);
	CHECK(framed == (octet_vector{'S', 'P', 'S', 'I', 'G', 3, 'c', 't', 'x', 'm', 's', 'g'}));
	CHECK(detail::frame_message("", msg) == (octet_vector{'S', 'P', 'S', 'I', 'G', 0, 'm', 's', 'g'}));
	CHECK_THROWS_AS(detail::frame_message(std::string(256, 'c'), msg), invalid_context);
}

}
