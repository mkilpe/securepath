// SPDX-License-Identifier: MIT

#pragma once

#include "certificate.hpp"
#include "public_key_id.hpp"
#include "types.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/types.hpp>

#include <cstdint>
#include <format>
#include <iosfwd>
#include <optional>
#include <string>

namespace securepath::crypto {

/**
 * Restrictions for the key certificate
 *
 * Host name restriction is a simple network host name. Another host name restriction is a subset
 * if it is the same domain or a sub-domain (case in-sensitive).
 */
class key_cert_restriction {
public:
	key_cert_restriction() = default;

	key_cert_restriction& hostname(std::string host) {
		hostname_ = std::move(host);
		return *this;
	}

	bool has_hostname() const {
		return !hostname_.empty();
	}

	std::string hostname() const {
		return hostname_;
	}

	/// is this restriction a subset of given restriction
	bool is_subset_of(key_cert_restriction const& other) const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & hostname_ & trailing_;
	}

private:
	std::string hostname_;
	serialisation::trailing_data trailing_;
};

bool operator==(key_cert_restriction const& l, key_cert_restriction const& r);
inline
bool operator!=(key_cert_restriction const& l, key_cert_restriction const& r) {
	return !(l == r);
}
std::ostream& operator<<(std::ostream& out, key_cert_restriction const& rest);
std::string to_string(key_cert_restriction const& rest);

/// merge two restrictions if possible, throw if they are not compatible with each other
key_cert_restriction merge(key_cert_restriction const&, key_cert_restriction const&);

/**
 * Certificate data to authenticate a public key
 */
class key_certificate_data {
public:
	enum {id = 1}; //certificate type id

	key_certificate_data() = default;
	key_certificate_data(public_key_id id, std::uint16_t ca = 0, key_cert_restriction rest = {}, octet_vector meta = {})
	: subject_(std::move(id))
	, ca_level_(ca)
	, restrictions_(std::move(rest))
	, metadata_(std::move(meta))
	{}

	/// get the subject key id of this certificate
	public_key_id subject() const { return subject_; }
	/// get the ca level this certificate grants. Notice that the signing key must have at least one higher ca level via certificates from root key
	std::uint16_t ca_level() const { return ca_level_; }
	key_cert_restriction restrictions() const { return restrictions_; }
	/// arbitrary metadata associated with the certificate
	octet_vector metadata() const { return metadata_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & subject_ & ca_level_ & restrictions_ & metadata_ & trailing_;
	}

private:
	int version_{1};
	// id of the public key this certificate is about
	public_key_id subject_;
	// ca level this certificate grants to the subject key
	std::uint16_t ca_level_{};
	// restrictions which apply when authenticating key
	key_cert_restriction restrictions_;
	// arbitrary metadata
	octet_vector metadata_;
	serialisation::trailing_data trailing_;
};

class private_key;

inline
certificate create_key_certificate(private_key const& key, public_key_id id, std::uint16_t ca = 0, key_cert_restriction rest = {}, octet_vector meta = {}) {
	certificate cert(key_certificate_data::id,
		serialisation::asn_der_serialise(key_certificate_data(std::move(id), ca, std::move(rest), std::move(meta))));
	cert.sign_me(key);
	return cert;
}

}

namespace std {
	template<>
	struct formatter<securepath::crypto::key_cert_restriction> : formatter<std::string> {
		auto format(securepath::crypto::key_cert_restriction const& rest, format_context& ctx) const {
			return formatter<std::string>::format(to_string(rest), ctx);
		}
	};
}
