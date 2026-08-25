// SPDX-License-Identifier: MIT

#pragma once

#include "certificate_id.hpp"
#include "certificate_revocation.hpp"
#include "signature.hpp"
#include "types.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/types.hpp>

#include <optional>

namespace securepath::crypto {

struct invalid_cert_type : crypto_error { using crypto_error::crypto_error; };

class private_key;
class public_key;

/**
 * Generic signed certificate: a type tag, opaque DER payload (key_certificate_data,
 * identifier_certificate_data, property_certificate_data, ...) and the issuer's
 * signature made with context "sp-cert". Not X.509. See doc/crypto.md.
 */
class certificate {
public:
	certificate(int type = 0, octet_vector data = {})
	: certificate_type_(type)
	, certificate_data_(std::move(data))
	{}

	/// checks the cryptographic validity but also returns false if the certificate has been revoked
	bool is_authentic(public_key const&) const;

	void sign_me(private_key const&);
	/// checks only if the certificate and possible revocation are cryptographically valid (use is_authentic to see if you can trust the certificate)
	bool verify_me(public_key const&) const;

	public_key_id issuer() const { return sig_.issuer(); }

	//note: the id is not valid until the certificate has been signed
	certificate_id id() const;

	int type() const { return certificate_type_; }

	template<typename CertType>
	CertType extract() const {
		if(CertType::id != certificate_type_) {
			throw invalid_cert_type();
		}
		return serialisation::asn_der_deserialise<CertType>(certificate_data_);
	}

	std::optional<certificate_revocation> revocation() const { return revocation_; }
	void set_revocation(certificate_revocation rev) { revocation_ = std::move(rev); }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & certificate_type_ & certificate_data_ & sig_ & revocation_ & trailing_;
	}

private:
	octet_vector make_sig_data() const;

private:
	int version_{1};
	int certificate_type_{};
	octet_vector certificate_data_;
	signature sig_;
	std::optional<certificate_revocation> revocation_;
	serialisation::trailing_data trailing_;
};

bool operator==(certificate const& l, certificate const& r);
bool operator!=(certificate const& l, certificate const& r);
bool operator<(certificate const& l, certificate const& r);

}
