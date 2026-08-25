// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/hkdf.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::crypto::test {

TEST_CASE("hkdf basic test", "[hkdf]") {
	octet_vector const key = random_octet_vector(32);
	octet_vector const iv = random_octet_vector(16);
	octet_vector const info = random_octet_vector(8);
	octet_vector const info2 = random_octet_vector(8);

	octet_vector hkdf_key1 = hkdf_sha3_512_derive_key(32, key, iv, info);
	octet_vector hkdf_key2 = hkdf_sha3_512_derive_key(32, key, iv, info);
	octet_vector hkdf_key3 = hkdf_sha3_512_derive_key(32, key, iv, info2);
	octet_vector hkdf_key4 = hkdf_sha3_512_derive_key(100, key, iv, info);

	CHECK(hkdf_key1.size() == 32);
	CHECK(hkdf_key4.size() == 100);
	CHECK(hkdf_key1 == hkdf_key2);
	CHECK(hkdf_key1 != hkdf_key3);
	CHECK(std::equal(hkdf_key1.begin(), hkdf_key1.end(), hkdf_key4.begin()));
}

TEST_CASE("hkdf known answer", "[hkdf][kat]") {
	// RFC 5869 test case 1
	octet_vector const ikm(22, 0x0b);
	octet_vector const salt = from_hex("000102030405060708090a0b0c");
	octet_vector const info = from_hex("f0f1f2f3f4f5f6f7f8f9");
	octet_vector okm = hkdf_derive_key(hash_algorithm::sha256, 42, ikm, salt, info);
	CHECK(to_hex(okm) == "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865");
}

}
