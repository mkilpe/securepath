// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/aes.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/types.hpp>

namespace securepath::crypto::test {

namespace {

void check_decrypt_with_key_and_iv(bool b, octet_vector const& data, octet_vector const& enc_data, octet_vector const& key, octet_vector const& iv) {
	octet_vector res(data.size());
	auto dec = create_aes_stream_decryptor(key, iv);
	dec->process(enc_data.data(), enc_data.data()+enc_data.size(), res.data());
	CHECK((data == res) == b);
}

void basic_aes_test(std::size_t data_size, std::size_t key_size, std::size_t iv_size) {
	octet_vector data = random_octet_vector(data_size);
	octet_vector key = random_octet_vector(key_size);
	octet_vector iv = random_octet_vector(iv_size);

	auto enc = create_aes_stream_encryptor(key, iv);
	auto dec = create_aes_stream_decryptor(key, iv);

	CHECK(enc->key_size() == aes_stream_cipher_key_size());
	CHECK(dec->key_size() == aes_stream_cipher_key_size());

	octet_vector enc_data(data.size());
	enc->process(data.data(), data.data()+data.size(), enc_data.data());

	octet_vector res(data.size());
	dec->process(enc_data.data(), enc_data.data()+enc_data.size(), res.data());

	CHECK(res == data);
}

void aes_invalid_key_length_test(std::size_t key_size, std::size_t iv_size) {
	octet_vector key = random_octet_vector(key_size);
	octet_vector iv = random_octet_vector(iv_size);

	CHECK_THROWS_AS(create_aes_stream_encryptor(key, iv), crypto_error);
	CHECK_THROWS_AS(create_aes_stream_decryptor(key, iv), crypto_error);
}

}

TEST_CASE("aes basic test", "[aes]") {
	basic_aes_test(512, aes_stream_cipher_key_size(), aes_stream_cipher_iv_size());
	basic_aes_test(0, aes_stream_cipher_key_size(), aes_stream_cipher_iv_size());
	basic_aes_test(1, aes_stream_cipher_key_size(), aes_stream_cipher_iv_size());
}

TEST_CASE("aes invalid key length", "[aes]") {
	aes_invalid_key_length_test(15, 15);
	aes_invalid_key_length_test(8, 8);
	aes_invalid_key_length_test(1, 1);
	aes_invalid_key_length_test(0, 0);
	aes_invalid_key_length_test(32, 15);
	aes_invalid_key_length_test(16, 16);
}

TEST_CASE("aes fail test", "[aes]") {
	octet_vector data = random_octet_vector(512);

	octet_vector key = random_octet_vector(aes_stream_cipher_key_size());
	octet_vector key2 = random_octet_vector(aes_stream_cipher_key_size());
	octet_vector key3 = key;
	key[key.size()-1] = '1';
	key3[key3.size()-1] = '2';

	octet_vector iv = random_octet_vector(aes_stream_cipher_iv_size());
	octet_vector iv2 = random_octet_vector(aes_stream_cipher_iv_size());
	octet_vector iv3 = iv;
	iv[iv.size()-1] = '1';
	iv3[iv3.size()-1] = '2';

	auto enc = create_aes_stream_encryptor(key, iv);
	octet_vector enc_data(data.size());
	enc->process(data.data(), data.data()+data.size(), enc_data.data());

	check_decrypt_with_key_and_iv(true, data, enc_data, key, iv);
	check_decrypt_with_key_and_iv(false, data, enc_data, key, iv2);
	check_decrypt_with_key_and_iv(false, data, enc_data, key, iv3);
	check_decrypt_with_key_and_iv(false, data, enc_data, key2, iv);
	check_decrypt_with_key_and_iv(false, data, enc_data, key2, iv2);
	check_decrypt_with_key_and_iv(false, data, enc_data, key2, iv3);
	check_decrypt_with_key_and_iv(false, data, enc_data, key3, iv);
	check_decrypt_with_key_and_iv(false, data, enc_data, key3, iv2);
	check_decrypt_with_key_and_iv(false, data, enc_data, key3, iv3);
}

TEST_CASE("aes multiple processes, different encrypted content", "[aes]") {
	octet_vector data = random_octet_vector(512);
	octet_vector key = random_octet_vector(aes_stream_cipher_key_size());
	octet_vector iv = random_octet_vector(aes_stream_cipher_iv_size());

	auto enc = create_aes_stream_encryptor(key, iv);
	auto dec = create_aes_stream_decryptor(key, iv);

	octet_vector enc_data1 = enc->process(data);
	octet_vector enc_data2 = enc->process(data);
	CHECK(enc_data1 != enc_data2);

	CHECK(dec->process(enc_data1) == data);
	CHECK(dec->process(enc_data2) == data);
}

TEST_CASE("aes process part of data", "[aes]") {
	octet_vector data = random_octet_vector(300);
	octet_vector key = random_octet_vector(aes_stream_cipher_key_size());
	octet_vector iv = random_octet_vector(aes_stream_cipher_iv_size());

	auto enc = create_aes_stream_encryptor(key, iv);
	auto dec = create_aes_stream_decryptor(key, iv);

	octet_vector o1(100);
	octet_vector o2(50);
	octet_vector o3(150);
	REQUIRE(data.size() == o1.size() + o2.size() + o3.size());

	enc->process(data.data(), data.data()+o1.size(), o1.data());
	enc->process(data.data() + o1.size(), data.data() + o1.size() + o2.size(), o2.data());
	enc->process(data.data() + o1.size() + o2.size(), data.data() + data.size(), o3.data());

	octet_vector res = dec->process(o1);
	octet_vector res2 = dec->process(o2);
	octet_vector res3 = dec->process(o3);
	res.insert(res.end(), res2.begin(), res2.end());
	res.insert(res.end(), res3.begin(), res3.end());

	CHECK(res == data);
}

TEST_CASE("aes seek", "[aes]") {
	octet_vector data = random_octet_vector(300);
	octet_vector key = random_octet_vector(aes_stream_cipher_key_size());
	octet_vector iv = random_octet_vector(aes_stream_cipher_iv_size());

	auto enc = create_aes_stream_encryptor(key, iv);
	octet_vector enc_data = enc->process(data);

	auto dec = create_aes_stream_decryptor(key, iv);
	dec->seek(100);
	octet_vector tail(enc_data.begin()+100, enc_data.end());
	CHECK(dec->process(tail) == octet_vector(data.begin()+100, data.end()));

	dec->seek(0);
	CHECK(dec->process(enc_data) == data);
}

}
