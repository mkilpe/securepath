// SPDX-License-Identifier: MIT

#include "aes_gcm.hpp"
#include "types.hpp"

#include <securepath/util/byte_order.hpp>
#include <securepath/util/error.hpp>

#include <botan/aead.h>
#include <botan/mem_ops.h>
#include <botan/secmem.h>
#include <botan/stream_cipher.h>

#include <optional>

namespace securepath::crypto {
namespace {

std::size_t const gcm_block_tag_size = 16;

class gcm_stream_cipher : public auth_stream_cipher {
public:
	gcm_stream_cipher(octet_vector const& key, bool encrypt)
	: key_(key.begin(), key.end())
	, encrypt_(encrypt)
	, ctr_(Botan::StreamCipher::create_or_throw("CTR-BE(AES-256,4)"))
	{
		if(key.size() != aes_gcm_key_size()) {
			throw invalid_key_size("aes gcm: key must be 32 octets");
		}
		ctr_->set_key(key_);
	}

	std::size_t key_size() const override { return aes_gcm_key_size(); }
	std::size_t default_tag_size() const override { return gcm_block_tag_size; }
	std::uint64_t max_data_size() const override { return aes_gcm_max_data_size(); }
	std::uint64_t max_auth_data_size() const override { return (std::uint64_t(1) << 61) - 1; }

	void process(std::uint8_t const* begin, std::uint8_t const* end, std::uint8_t* out) override {
		check_usable();
		std::size_t const size = static_cast<std::size_t>(end-begin);
		if(size > max_data_size() - plain_.size()) {
			throw error(securepath::errc::constraint_violation, "aes gcm: message too long for one nonce");
		}
		ctr_->cipher(begin, out, size);
		std::uint8_t const* plain = encrypt_ ? begin : out;
		plain_.insert(plain_.end(), plain, plain+size);
	}

	void process_auth(std::uint8_t const* begin, std::uint8_t const* end) override {
		check_usable();
		aad_.insert(aad_.end(), begin, end);
	}

	void tag(std::uint8_t* out, std::size_t tag_size) override {
		check_usable();
		if(tag_size == 0 || tag_size > gcm_block_tag_size) {
			throw error(securepath::errc::invalid_argument, "aes gcm: tag size must be 1..16");
		}
		auto gcm = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
		gcm->set_key(key_);
		gcm->set_associated_data(aad_);
		gcm->start(nonce_);
		Botan::secure_vector<std::uint8_t> buf(plain_);
		gcm->finish(buf);
		Botan::copy_mem(out, buf.data() + buf.size() - gcm_block_tag_size, tag_size);
		after_tag();
	}

protected:
	/// (re)start a message with the given 12 octet nonce
	void start(octet_vector nonce) {
		if(nonce.size() != aes_gcm_iv_size()) {
			throw invalid_iv_size("aes gcm: nonce must be 12 octets");
		}
		nonce_ = std::move(nonce);
		octet_vector j0(nonce_);
		j0.insert(j0.end(), {0, 0, 0, 2}); // GCM's first data counter block for 96-bit nonces
		ctr_->set_iv(j0.data(), j0.size());
		aad_.clear();
		plain_.clear();
	}

	void finish() {
		finished_ = true;
		aad_.clear();
		plain_.clear();
	}

	virtual void after_tag() = 0;

private:
	void check_usable() const {
		if(finished_) {
			throw error(securepath::errc::invalid_state, "aes gcm: cipher already finished with tag()");
		}
	}

private:
	Botan::secure_vector<std::uint8_t> key_;
	bool encrypt_{};
	bool finished_{};
	std::unique_ptr<Botan::StreamCipher> ctr_;
	octet_vector nonce_;
	octet_vector aad_;
	Botan::secure_vector<std::uint8_t> plain_;
};

class single_message_gcm : public gcm_stream_cipher {
public:
	single_message_gcm(octet_vector const& key, octet_vector const& nonce, bool encrypt)
	: gcm_stream_cipher(key, encrypt)
	{
		start(nonce);
	}

	std::size_t iv_size() const override { return aes_gcm_iv_size(); }

	void seek(std::uint64_t) override {
		throw error(securepath::errc::not_supported, "aes gcm: seek is only available with the implicit counter variant");
	}

protected:
	void after_tag() override {
		finish();
	}
};

class implicit_counter_gcm : public gcm_stream_cipher {
public:
	implicit_counter_gcm(octet_vector const& key, octet_vector const& iv, std::uint64_t counter, bool encrypt)
	: gcm_stream_cipher(key, encrypt)
	, iv_(iv)
	, counter_(counter)
	{
		if(iv.size() != aes_gcm_implicit_counter_iv_size()) {
			throw invalid_iv_size("aes gcm implicit counter: iv must be 4 octets");
		}
		start(next_nonce());
	}

	std::size_t iv_size() const override { return aes_gcm_implicit_counter_iv_size(); }

	void seek(std::uint64_t counter) override {
		counter_ = counter;
		start(next_nonce());
	}

protected:
	void after_tag() override {
		start(next_nonce());
	}

private:
	octet_vector next_nonce() {
		std::uint8_t counter[8];
		to_endian(counter, counter_++);
		octet_vector nonce(iv_);
		nonce.insert(nonce.end(), counter, counter+sizeof(counter));
		return nonce;
	}

private:
	octet_vector iv_;
	std::uint64_t counter_{};
};

}

std::size_t aes_gcm_key_size() {
	return 32;
}

std::size_t aes_gcm_iv_size() {
	return 12;
}

std::size_t aes_gcm_tag_size() {
	return gcm_block_tag_size;
}

std::uint64_t aes_gcm_max_data_size() {
	return ((std::uint64_t(1)<<39)-256)/8;
}

std::size_t aes_gcm_implicit_counter_iv_size() {
	return 4;
}

bool tag_matches(octet_vector const& l, octet_vector const& r) {
	return l.size() == r.size() && Botan::constant_time_compare(l, r);
}

auth_stream_cipher_ptr create_aes_gcm_stream_encryptor(octet_vector const& key, octet_vector const& iv) {
	return std::make_unique<single_message_gcm>(key, iv, true);
}

auth_stream_cipher_ptr create_aes_gcm_stream_decryptor(octet_vector const& key, octet_vector const& iv) {
	return std::make_unique<single_message_gcm>(key, iv, false);
}

auth_stream_cipher_ptr create_aes_gcm_implicit_counter_stream_encryptor(octet_vector const& key, octet_vector const& iv, std::uint64_t counter) {
	return std::make_unique<implicit_counter_gcm>(key, iv, counter, true);
}

auth_stream_cipher_ptr create_aes_gcm_implicit_counter_stream_decryptor(octet_vector const& key, octet_vector const& iv, std::uint64_t counter) {
	return std::make_unique<implicit_counter_gcm>(key, iv, counter, false);
}

}
