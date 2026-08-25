// SPDX-License-Identifier: MIT

#pragma once

#include "encrypted_key.hpp"
#include "public_key.hpp"

#include <securepath/serialisation/deque.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>
#include <deque>

namespace securepath::crypto {

class private_key;

/// data encrypted once with AES-256-GCM, the content key enveloped for each recipient
class enveloped_content {
public:
	enveloped_content() = default;
	enveloped_content(std::deque<encrypted_key> keys, octet_vector data, octet_vector iv, octet_vector tag);

	/// throws wrong_key if the private key is not a recipient, invalid_tag if the content was modified
	octet_vector decrypt(private_key const&) const;

	void add(encrypted_key key);
	bool empty() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & keys_ & iv_ & encrypted_ & tag_;
	}

private:
	std::uint32_t version_{0};
	std::deque<encrypted_key> keys_;
	octet_vector iv_;
	octet_vector encrypted_;
	octet_vector tag_;
};

/// builds an envelope incrementally; encrypt_key() lets recipients be added to an existing result
class enveloper {
public:
	enveloper(octet_vector data);

	void add(public_key const&);
	encrypted_key encrypt_key(public_key const& pk) const;
	enveloped_content result() const;

private:
	octet_vector data_;
	octet_vector sym_key_;
	std::deque<encrypted_key> keys_;
};

enveloped_content envelope(public_key const& key, octet_vector const& data);
enveloped_content envelope(std::deque<public_key> const& key, octet_vector const& data);

octet_vector decrypt(enveloped_content const&, private_key const&);

}
