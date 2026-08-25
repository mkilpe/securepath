// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/types.hpp>
#include <securepath/util/conversions.hpp>
#include <securepath/util/error.hpp>

#include <botan/aead.h>

#include <algorithm>

namespace securepath::crypto::test {

namespace {

void check_decrypt_result_with_auth(bool b, octet_vector const& data, octet_vector const& enc_data, octet_vector const& key, octet_vector const& iv, octet_vector const& auth) {
	auto dec = create_aes_gcm_stream_decryptor(key, iv);
	dec->process_auth(auth);
	octet_vector result = dec->process(enc_data);
	CHECK((data == result) == b);
	CHECK(data.size() == result.size());
}

void check_decrypt_result(bool b, octet_vector const& data, octet_vector const& enc_data, octet_vector const& key, octet_vector const& iv) {
	check_decrypt_result_with_auth(b, data, enc_data, key, iv, iv);
}

void aes_gcm_invalid_key_length_test(std::size_t key_size, std::size_t iv_size) {
	octet_vector key = random_octet_vector(key_size);
	octet_vector iv = random_octet_vector(iv_size);
	CHECK_THROWS_AS(create_aes_gcm_stream_encryptor(key, iv), crypto_error);
	CHECK_THROWS_AS(create_aes_gcm_stream_decryptor(key, iv), crypto_error);
}

/// reference: Botan's one-shot AES-256/GCM
std::pair<octet_vector, octet_vector> reference_gcm(octet_vector const& key, octet_vector const& iv, octet_vector const& aad, octet_vector const& plain) {
	auto gcm = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
	gcm->set_key(key);
	gcm->set_associated_data(aad);
	gcm->start(iv);
	Botan::secure_vector<std::uint8_t> buf(plain.begin(), plain.end());
	gcm->finish(buf);
	return {octet_vector(buf.begin(), buf.end()-16), octet_vector(buf.end()-16, buf.end())};
}

}

TEST_CASE("aes gcm basic test", "[aes_gcm][aes]") {
	octet_vector data = random_octet_vector(512);
	octet_vector iv = random_octet_vector(aes_gcm_iv_size());
	octet_vector key = random_octet_vector(aes_gcm_key_size());

	auto enc = create_aes_gcm_stream_encryptor(key, iv);
	enc->process_auth(iv);
	octet_vector enc_data = enc->process(data);
	octet_vector tag1 = enc->tag();

	auto dec = create_aes_gcm_stream_decryptor(key, iv);
	dec->process_auth(iv);
	octet_vector result = dec->process(enc_data);
	octet_vector tag2 = dec->tag();

	CHECK(data == result);
	CHECK(tag1 == tag2);
	CHECK(tag_matches(tag1, tag2));
	CHECK(tag1.size() == aes_gcm_tag_size());
	CHECK(enc->iv_size() == aes_gcm_iv_size());
	CHECK(enc->key_size() == aes_gcm_key_size());
	CHECK(enc->max_data_size() == aes_gcm_max_data_size());
}

TEST_CASE("aes gcm fail test", "[aes_gcm][aes]") {
	octet_vector data = random_octet_vector(512);
	octet_vector iv = random_octet_vector(aes_gcm_iv_size());
	octet_vector iv2 = random_octet_vector(aes_gcm_iv_size());
	octet_vector key = random_octet_vector(aes_gcm_key_size());
	octet_vector key2 = random_octet_vector(aes_gcm_key_size());

	auto enc = create_aes_gcm_stream_encryptor(key, iv);
	enc->process_auth(iv);
	octet_vector enc_data = enc->process(data);

	check_decrypt_result(true, data, enc_data, key, iv);
	check_decrypt_result(false, data, enc_data, key2, iv);
	check_decrypt_result(false, data, enc_data, key, iv2);
	check_decrypt_result_with_auth(false, data, enc_data, key, iv2, iv);
}

TEST_CASE("aes gcm fail test 2", "[aes_gcm]") {
	octet_vector data = random_octet_vector(512);
	octet_vector key1 = random_octet_vector(aes_gcm_key_size());
	octet_vector key2 = key1;
	key1[key1.size()-1] = '1';
	key2[key1.size()-1] = '2';
	octet_vector iv1 = random_octet_vector(aes_gcm_iv_size());
	octet_vector iv2 = iv1;
	iv1[iv1.size()-1] = '1';
	iv2[iv2.size()-1] = '2';

	auto enc = create_aes_gcm_stream_encryptor(key1, iv1);
	enc->process_auth(iv1);
	octet_vector enc_data = enc->process(data);

	check_decrypt_result(true, data, enc_data, key1, iv1);
	check_decrypt_result(false, data, enc_data, key1, iv2);
	check_decrypt_result(false, data, enc_data, key2, iv1);
	check_decrypt_result(false, data, enc_data, key2, iv2);
	check_decrypt_result_with_auth(false, data, enc_data, key1, iv2, iv1);
}

TEST_CASE("aes gcm invalid key length", "[aes_gcm]") {
	aes_gcm_invalid_key_length_test(15, 15);
	aes_gcm_invalid_key_length_test(8, 8);
	aes_gcm_invalid_key_length_test(1, 1);
	aes_gcm_invalid_key_length_test(0, 0);
	aes_gcm_invalid_key_length_test(32, 16);
	aes_gcm_invalid_key_length_test(32, 32);
	aes_gcm_invalid_key_length_test(16, 12);
}

TEST_CASE("aes gcm matches standard gcm", "[aes_gcm][kat]") {
	octet_vector key = random_octet_vector(aes_gcm_key_size());
	octet_vector iv = random_octet_vector(aes_gcm_iv_size());
	octet_vector aad = random_octet_vector(37);
	octet_vector data = random_octet_vector(1000);
	auto [ref_ct, ref_tag] = reference_gcm(key, iv, aad, data);

	auto enc = create_aes_gcm_stream_encryptor(key, iv);
	enc->process_auth(aad);
	octet_vector ct = enc->process(octet_vector(data.begin(), data.begin()+333));
	octet_vector ct2 = enc->process(octet_vector(data.begin()+333, data.end()));
	ct.insert(ct.end(), ct2.begin(), ct2.end());
	CHECK(ct == ref_ct);
	CHECK(enc->tag() == ref_tag);

	auto dec = create_aes_gcm_stream_decryptor(key, iv);
	dec->process_auth(aad);
	CHECK(dec->process(ct) == data);
	CHECK(dec->tag() == ref_tag);
}

TEST_CASE("aes gcm nist known answers", "[aes_gcm][kat]") {
	// NIST GCM test cases 13 and 14 (AES-256, zero key and nonce)
	octet_vector key(32, 0);
	octet_vector iv(12, 0);

	auto enc13 = create_aes_gcm_stream_encryptor(key, iv);
	CHECK(to_hex(enc13->tag()) == "530F8AFBC74536B9A963B4F1C4CB738B");

	auto enc14 = create_aes_gcm_stream_encryptor(key, iv);
	octet_vector ct = enc14->process(octet_vector(16, 0));
	CHECK(to_hex(ct) == "CEA7403D4D606B6E074EC5D3BAF39D18");
	CHECK(to_hex(enc14->tag()) == "D0D1C8A799996BF0265B98B5D48AB919");
}

TEST_CASE("aes gcm aad after data", "[aes_gcm]") {
	// the tag covers AAD = all process_auth data and C = all ciphertext, whatever the call order
	octet_vector key = random_octet_vector(aes_gcm_key_size());
	octet_vector iv = random_octet_vector(aes_gcm_iv_size());
	octet_vector aad1 = random_octet_vector(20);
	octet_vector aad2 = random_octet_vector(30);
	octet_vector data1 = random_octet_vector(100);
	octet_vector data2 = random_octet_vector(100);

	octet_vector aad(aad1);
	aad.insert(aad.end(), aad2.begin(), aad2.end());
	octet_vector data(data1);
	data.insert(data.end(), data2.begin(), data2.end());
	auto [ref_ct, ref_tag] = reference_gcm(key, iv, aad, data);

	auto enc = create_aes_gcm_stream_encryptor(key, iv);
	enc->process_auth(aad1);
	octet_vector ct = enc->process(data1);
	enc->process_auth(aad2);
	octet_vector ct2 = enc->process(data2);
	ct.insert(ct.end(), ct2.begin(), ct2.end());

	CHECK(ct == ref_ct);
	CHECK(enc->tag() == ref_tag);

	auto dec = create_aes_gcm_stream_decryptor(key, iv);
	dec->process_auth(aad1);
	octet_vector plain = dec->process(octet_vector(ct.begin(), ct.begin()+100));
	dec->process_auth(aad2);
	octet_vector plain2 = dec->process(octet_vector(ct.begin()+100, ct.end()));
	plain.insert(plain.end(), plain2.begin(), plain2.end());
	CHECK(plain == data);
	CHECK(dec->tag() == ref_tag);
}

TEST_CASE("aes gcm truncated tag and state", "[aes_gcm]") {
	octet_vector key = random_octet_vector(aes_gcm_key_size());
	octet_vector iv = random_octet_vector(aes_gcm_iv_size());
	octet_vector data = random_octet_vector(64);

	auto enc = create_aes_gcm_stream_encryptor(key, iv);
	enc->process(data);
	octet_vector full(16);
	auto enc2 = create_aes_gcm_stream_encryptor(key, iv);
	enc2->process(data);
	enc2->tag(full.data(), full.size());

	octet_vector truncated(12);
	enc->tag(truncated.data(), truncated.size());
	CHECK(std::equal(truncated.begin(), truncated.end(), full.begin()));

	// finished after tag()
	CHECK_THROWS_AS(enc->process(data), error);
	CHECK_THROWS_AS(enc->process_auth(data), error);
	CHECK_THROWS_AS(enc->tag(), error);
	CHECK_THROWS_AS(enc2->seek(0), error);

	auto enc3 = create_aes_gcm_stream_encryptor(key, iv);
	octet_vector out(17);
	CHECK_THROWS_AS(enc3->tag(out.data(), 17), error);
	CHECK_THROWS_AS(enc3->tag(out.data(), 0), error);
}

TEST_CASE("aes gcm implicit counter basic test", "[aes_gcm][aes]") {
	octet_vector key = random_octet_vector(aes_gcm_key_size());
	octet_vector iv  = random_octet_vector(aes_gcm_implicit_counter_iv_size());

	std::vector<octet_vector> data;
	std::vector<octet_vector> enc_data;
	std::vector<octet_vector> tag_data;

	auto buf = random_octet_vector(1024*8);

	auto encryptor = create_aes_gcm_implicit_counter_stream_encryptor(key, iv);
	CHECK(encryptor->iv_size() == aes_gcm_implicit_counter_iv_size());

	for(int i = 0; i != 10; ++i) {
		data.push_back(buf);
		enc_data.push_back(encryptor->process(data.back()));
		tag_data.push_back(encryptor->tag());
	}

	auto decryptor = create_aes_gcm_implicit_counter_stream_decryptor(key, iv);

	for(std::size_t i = 0; i != enc_data.size(); ++i) {
		CHECK(decryptor->process(enc_data[i]) == data[i]);
		CHECK(decryptor->tag() == tag_data[i]);
	}

	// check we actually used different nonces and so the cipher text and tag differs
	for(auto&& v : enc_data) {
		CHECK(std::count(enc_data.begin(), enc_data.end(), v) == 1);
	}
	for(auto&& v : tag_data) {
		CHECK(std::count(tag_data.begin(), tag_data.end(), v) == 1);
	}

	//do out of order decryption by setting the implicit counter
	decryptor->seek(4);
	CHECK(decryptor->process(enc_data[4]) == data[4]);
	CHECK(decryptor->tag() == tag_data[4]);

	decryptor->seek(7);
	CHECK(decryptor->process(enc_data[7]) == data[7]);
	CHECK(decryptor->tag() == tag_data[7]);

	// start sequence from different value
	auto decryptor2 = create_aes_gcm_implicit_counter_stream_decryptor(key, iv, 2);
	for(std::size_t i = 2; i != enc_data.size(); ++i) {
		CHECK(decryptor2->process(enc_data[i]) == data[i]);
		CHECK(decryptor2->tag() == tag_data[i]);
	}

	// check that using different start sequence fails to decrypt
	auto decryptor3 = create_aes_gcm_implicit_counter_stream_decryptor(key, iv, 2);
	CHECK(decryptor3->process(enc_data[0]) != data[0]);
	CHECK(decryptor3->tag() != tag_data[0]);
}

TEST_CASE("aes gcm implicit counter matches standard gcm", "[aes_gcm][kat]") {
	octet_vector key = random_octet_vector(aes_gcm_key_size());
	octet_vector iv  = random_octet_vector(aes_gcm_implicit_counter_iv_size());
	octet_vector data = random_octet_vector(100);

	auto enc = create_aes_gcm_implicit_counter_stream_encryptor(key, iv, 5);
	octet_vector ct = enc->process(data);
	octet_vector tag = enc->tag();

	octet_vector nonce(iv);
	nonce.insert(nonce.end(), {0, 0, 0, 0, 0, 0, 0, 5});
	auto [ref_ct, ref_tag] = reference_gcm(key, nonce, {}, data);
	CHECK(ct == ref_ct);
	CHECK(tag == ref_tag);

	CHECK_THROWS_AS(create_aes_gcm_implicit_counter_stream_encryptor(key, random_octet_vector(12)), crypto_error);
}

}
