// SPDX-License-Identifier: MIT

#pragma once

#include "certificate.hpp"
#include "key_certificate.hpp"
#include "public_key.hpp"
#include "public_key_id.hpp"
#include "types.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/serialisation/vector.hpp>

#include <cstdint>
#include <format>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace securepath::crypto {

class public_key_access;
class certificate_access;

struct key_cert_pair {
	public_key subject;
	certificate cert;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & subject & cert;
	}
};

/**
 * Chain of certificates to authenticate a public key. The chain is always from known root key to a single arbitrary public key.
 * All the certificates must be key certificates
 */
class certificate_chain {
public:
	using iterator = std::vector<key_cert_pair>::const_iterator;

	certificate_chain() = default;
	certificate_chain(public_key_id root, std::vector<key_cert_pair> chain);

	/// get the id of the root key that was used to sign first certificate
	public_key_id root_key_id() const { return root_key_id_; }

	/// get iterator to the first key certificate pair (signed by root)
	iterator begin() const { return chain_.begin(); }
	/// get end iterator
	iterator end() const { return chain_.end(); }

	/// check whether the chain contains data, does not do any crypto checks
	bool is_valid() const;

	/// get the public key this certificate chain authenticates
	public_key subject() const;

	/// verify if the chain is cryptographically valid
	bool is_authentic(public_key_access const& keys, certificate_access const& certs) const;

	/// verify if the chain is cryptographically valid and if restriction is fulfilled
	bool is_authentic(public_key_access const& keys, certificate_access const& certs, key_cert_restriction const& rest) const;

	/// gives the ca level for subject this chain has
	std::uint16_t subject_ca_level() const;

	/// gives the restrictions for subject this chain has
	key_cert_restriction subject_restrictions() const;

	/// add link to the end of the chain, first overload cannot be used with empty chain as it does not have the root key
	void add_link(public_key key, certificate cert);
	void add_link(public_key_access const& keys, public_key key, certificate cert);

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & root_key_id_ & chain_;
	}

private:
	int version_{1};
	public_key_id root_key_id_;
	std::vector<key_cert_pair> chain_;
};

std::string to_string(certificate_chain const&);
std::ostream& operator<<(std::ostream& out, certificate_chain const&);

/// Create certificate chain for public key if such exists
std::optional<certificate_chain> create_certificate_chain(public_key const& subject, public_key_access const& keys, certificate_access const& certs);

}

namespace std {
	template<>
	struct formatter<securepath::crypto::certificate_chain> : formatter<std::string> {
		auto format(securepath::crypto::certificate_chain const& chain, format_context& ctx) const {
			return formatter<std::string>::format(to_string(chain), ctx);
		}
	};
}
