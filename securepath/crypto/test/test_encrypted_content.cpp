// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/encrypted_content.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/types.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

TEST_CASE("encrypted_content basic test", "[encrypted_content]") {
	octet_vector const key  = random_octet_vector(aes_gcm_key_size());
	octet_vector const data = random_octet_vector(512);

	encrypted_content content = encrypt(data, key);
	CHECK(!content.empty());
	CHECK(content.iv().size() == aes_gcm_iv_size());
	CHECK(content.tag().size() == aes_gcm_tag_size());

	CHECK(decrypt(content, key) == data);

	auto ser = serialisation::asn_der_serialise(content);
	encrypted_content content2 = serialisation::asn_der_deserialise<encrypted_content>(ser);
	CHECK(decrypt(content2, key) == data);
}

TEST_CASE("encrypted_content bad key", "[encrypted_content][security]") {
	octet_vector const key  = random_octet_vector(aes_gcm_key_size());
	octet_vector const data = random_octet_vector(512);
	octet_vector const bad_key  = random_octet_vector(aes_gcm_key_size());

	encrypted_content content = encrypt(data, key);
	CHECK(!content.empty());

	CHECK_THROWS_AS(decrypt(content, bad_key), invalid_tag);
	CHECK_THROWS_AS(encrypt(data, random_octet_vector(13)), crypto_error);

	octet_vector modified = content.content();
	modified[10] ^= 1;
	encrypted_content tampered(modified, content.iv(), content.tag());
	CHECK_THROWS_AS(decrypt(tampered, key), invalid_tag);
}

}
