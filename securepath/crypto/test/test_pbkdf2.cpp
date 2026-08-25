// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/password_hash.hpp>
#include <securepath/crypto/pbkdf2.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/types.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::crypto::test {

TEST_CASE("pbkdf2 basic test", "[pbkdf2]") {
	octet_vector const password = random_octet_vector(12);
	octet_vector const salt = random_octet_vector(16);
	std::size_t s = 32;

	CHECK(pbkdf2_hmac_sha1(s, password, salt) == pbkdf2_hmac_sha1(s, password, salt));
	CHECK(pbkdf2_hmac_sha1(s, password, salt).size() == s);
	CHECK(pbkdf2_hmac_sha512(s, password, salt) == pbkdf2_hmac_sha512(s, password, salt));
	CHECK(pbkdf2_hmac_sha512(s, password, salt) != pbkdf2_hmac_sha1(s, password, salt));
}

TEST_CASE("pbkdf2 test", "[pbkdf2]") {
	octet_vector const password1 = random_octet_vector(12);
	octet_vector const password2 = random_octet_vector(12);
	octet_vector const salt1 = random_octet_vector(16);
	octet_vector const salt2 = random_octet_vector(16);
	std::size_t s = 32;
	std::size_t s2 = 33;

	CHECK(pbkdf2_hmac_sha1(s, password1, salt1, 1000) != pbkdf2_hmac_sha1(s, password1, salt1, 999));
	CHECK(pbkdf2_hmac_sha1(s, password1, salt1) != pbkdf2_hmac_sha1(s, password2, salt1));
	CHECK(pbkdf2_hmac_sha1(s, password1, salt1) != pbkdf2_hmac_sha1(s, password1, salt2));
	CHECK(pbkdf2_hmac_sha1(s2, password1, salt1).size() == s2);

	CHECK_THROWS_AS(pbkdf2_hmac_sha512(s, octet_vector{}, salt1), crypto_error);
	CHECK_THROWS_AS(pbkdf2_hmac_sha512(s, password1, octet_vector{}), crypto_error);
}

TEST_CASE("pbkdf2 known answers", "[pbkdf2][kat]") {
	// RFC 6070
	std::string const p = "password";
	std::string const s = "salt";
	octet_vector const password(p.begin(), p.end());
	octet_vector const salt(s.begin(), s.end());
	CHECK(to_hex(pbkdf2_hmac_sha1(20, password, salt, 1)) == "0C60C80F961F0E71F3A9B524AF6012062FE037A6");
	CHECK(to_hex(pbkdf2_hmac_sha1(20, password, salt, 2)) == "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957");
	// PBKDF2-HMAC-SHA512, same inputs, 1 iteration (independently published vector)
	CHECK(to_hex(pbkdf2_hmac_sha512(64, password, salt, 1)) == "867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE");
}

TEST_CASE("argon2id", "[password_hash]") {
	octet_vector const password = random_octet_vector(12);
	octet_vector const salt = random_octet_vector(16);
	argon2id_parameters const fast{8192, 1, 1};

	octet_vector k1 = argon2id(32, password, salt, fast);
	CHECK(k1.size() == 32);
	CHECK(k1 == argon2id(32, password, salt, fast));
	CHECK(k1 != argon2id(32, password, random_octet_vector(16), fast));
	CHECK(k1 != argon2id(32, random_octet_vector(12), salt, fast));
	CHECK_THROWS_AS(argon2id(32, password, random_octet_vector(4), fast), crypto_error);
}

}
