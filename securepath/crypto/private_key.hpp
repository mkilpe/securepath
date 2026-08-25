// SPDX-License-Identifier: MIT

#pragma once

#include "public_key.hpp"
#include "signature.hpp"
#include "suite.hpp"
#include "types.hpp"

#include <securepath/serialisation/deserialiser.hpp>
#include <securepath/serialisation/serialiser.hpp>
#include <securepath/util/types.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace securepath::crypto {

class private_key_impl;

/**
 * Private half of an identity: ML-DSA signing key + hybrid KEM key of one suite.
 * Create with generate_private_key() (key_generation.hpp). See doc/crypto.md.
 */
class private_key {
public:
	private_key();
	private_key(std::shared_ptr<private_key_impl>);

	public_key_id id() const;
	crypto::suite suite() const;
	crypto::public_key public_key() const;
	bool is_valid() const;

	/// signs and sets the public key which matches this private key
	void set_public_key(crypto::public_key);

	/// context gives domain separation between uses ("" for application data, "sp-cert", ...); max 255 octets
	signature sign(octet_vector const& data, std::string_view context = {}) const;
	/// decrypt data from public_key::encrypt(); throws bad_ciphertext
	octet_vector decrypt(octet_vector const& ciphertext) const;

	/// arbitrary data stored with the key; empty data erases the entry
	void metadata(std::string const& key, octet_vector data);
	octet_vector metadata(std::string const& key) const;

	void serialise(serialisation::serialiser&);
	void serialise(serialisation::deserialiser&);

private:
	std::shared_ptr<private_key_impl> impl_;
};

}
