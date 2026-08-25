// SPDX-License-Identifier: MIT

#pragma once

#include "certificate_id.hpp"
#include "private_key.hpp"
#include "signature.hpp"
#include "types.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/util/types.hpp>

namespace securepath::crypto {

class certificate;

/// Signed statement by the certificate issuer that the certificate is no longer valid (context "sp-revocation")
class certificate_revocation {
public:
	explicit certificate_revocation(certificate_id cid = {})
	: cid_(std::move(cid))
	{}

	void sign_me(private_key const&);
	bool verify_me(public_key const&) const;

	certificate_id id() const { return cid_; }
	public_key_id issuer() const { return sig_.issuer(); }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & cid_ & sig_ & trailing_;
	}

private:
	octet_vector make_sig_data() const;

private:
	int version_{1};
	certificate_id cid_;
	signature sig_;
	serialisation::trailing_data trailing_;
};

bool operator==(certificate_revocation const& l, certificate_revocation const& r);
bool operator!=(certificate_revocation const& l, certificate_revocation const& r);
bool operator<(certificate_revocation const& l, certificate_revocation const& r);

/// revoke the certificate with the issuer's key, throws error(errc::invalid_public_key) if the key is not the issuer
certificate_revocation revoke_certificate(private_key const& key, certificate cert);

}
