// SPDX-License-Identifier: MIT

#include "aes.hpp"
#include "types.hpp"

#include <botan/stream_cipher.h>

namespace securepath::crypto {
namespace {

class aes_ctr_stream_cipher : public stream_cipher {
public:
	aes_ctr_stream_cipher(octet_vector const& key, octet_vector const& iv)
	: cipher_(Botan::StreamCipher::create_or_throw("CTR-BE(AES-256)"))
	{
		if(key.size() != aes_stream_cipher_key_size()) {
			throw invalid_key_size("aes: key must be 32 octets");
		}
		if(iv.size() != aes_stream_cipher_iv_size()) {
			throw invalid_iv_size("aes: iv must be 16 octets");
		}
		cipher_->set_key(key);
		cipher_->set_iv(iv.data(), iv.size());
	}

	std::size_t key_size() const override {
		return aes_stream_cipher_key_size();
	}

	void process(std::uint8_t const* begin, std::uint8_t const* end, std::uint8_t* out) override {
		cipher_->cipher(begin, out, static_cast<std::size_t>(end-begin));
	}

	void seek(std::uint64_t pos) override {
		cipher_->seek(pos);
	}

private:
	std::unique_ptr<Botan::StreamCipher> cipher_;
};

}

std::size_t aes_stream_cipher_key_size() {
	return 32;
}

std::size_t aes_stream_cipher_iv_size() {
	return 16;
}

stream_cipher_ptr create_aes_stream_encryptor(octet_vector const& key, octet_vector const& iv) {
	return std::make_unique<aes_ctr_stream_cipher>(key, iv);
}

stream_cipher_ptr create_aes_stream_decryptor(octet_vector const& key, octet_vector const& iv) {
	return std::make_unique<aes_ctr_stream_cipher>(key, iv);
}

}
