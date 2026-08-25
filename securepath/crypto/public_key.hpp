// SPDX-License-Identifier: MIT

#pragma once

#include "public_key_id.hpp"
#include "suite.hpp"
#include "types.hpp"

#include <securepath/serialisation/deserialiser.hpp>
#include <securepath/serialisation/serialiser.hpp>

#include <memory>
#include <set>
#include <string_view>

namespace securepath::crypto {

class signature;
class public_key_impl;
class private_key;
class certificate_id;

/**
 * Public half of an identity: ML-DSA verification key + hybrid KEM key of one suite,
 * self-signed together with the referenced certificate ids. See doc/crypto.md.
 */
class public_key {
public:
	public_key();
	public_key(std::shared_ptr<public_key_impl>);

	public_key_id id() const;
	crypto::suite suite() const;
	/// true when the key carries key material (a default constructed key does not)
	bool is_valid() const;

	/// hybrid KEM + AES-256-GCM encryption for the owner of this key; throws invalid_key if the key is not usable
	octet_vector encrypt(octet_vector const& plaintext) const;
	/// verify a signature made with private_key::sign() using the same context
	bool verify(signature const&, octet_vector const& data, std::string_view context = {}) const;

	/// sign this public key with given private key, the key id must be the same as for this public key
	void sign_me(private_key const& key);
	bool verify_me() const;

	///add or remove cert id, notice that you need to re-sign the public key afterwards
	void add_certificate_id(certificate_id);
	void remove_certificate_id(certificate_id);
	std::set<certificate_id> get_cert_ids() const;

	/// check if the public key references a certificate
	bool references_certificate(certificate_id const&) const;

	void serialise(serialisation::serialiser&);
	void serialise(serialisation::deserialiser&);

private:
	std::shared_ptr<public_key_impl> impl_;
};

}
