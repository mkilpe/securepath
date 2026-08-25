// SPDX-License-Identifier: MIT

#pragma once

#include "public_key_id.hpp"
#include "types.hpp"

#include <securepath/serialisation/sequence.hpp>

#include <cstdint>

namespace securepath::crypto {

class public_key;
class private_key;

struct wrong_key : crypto_error { using crypto_error::crypto_error; };

/// a symmetric key encrypted for one recipient with public_key::encrypt()
class encrypted_key {
public:
	encrypted_key() = default;
	encrypted_key(public_key_id pid, octet_vector data)
	: encryptor_id_(std::move(pid))
	, data_(std::move(data))
	{}

	public_key_id key_id() const { return encryptor_id_; }
	octet_vector data() const { return data_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & encryptor_id_ & data_;
	}

private:
	std::uint32_t version_{1};
	public_key_id encryptor_id_;
	octet_vector data_;
};

encrypted_key encrypt_key(public_key const&, octet_vector const& key);
/// throws wrong_key if the key was not encrypted for this private key, bad_ciphertext if it cannot be decrypted
octet_vector decrypt_key(private_key const&, encrypted_key const& key);

}
