// SPDX-License-Identifier: MIT

#include "certificate_revocation.hpp"

#include "certificate.hpp"
#include "error.hpp"
#include "private_key.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto {

namespace {
std::string_view const revocation_context = "sp-revocation";
}

octet_vector certificate_revocation::make_sig_data() const {
	using namespace serialisation;
	octet_vector v;
	octet_vector_ostream ss(v);
	auto ser = make_serialiser<asn_der_encoder<octet_vector_ostream>>(ss);
	sequence<serialiser> seq(ser);
	seq & version_ & cid_ & trailing_;
	return v;
}

void certificate_revocation::sign_me(private_key const& key) {
	sig_ = key.sign(make_sig_data(), revocation_context);
}

bool certificate_revocation::verify_me(public_key const& key) const {
	return key.verify(sig_, make_sig_data(), revocation_context);
}

bool operator==(certificate_revocation const& l, certificate_revocation const& r) {
	return l.id() == r.id();
}

bool operator!=(certificate_revocation const& l, certificate_revocation const& r) {
	return !(l == r);
}

bool operator<(certificate_revocation const& l, certificate_revocation const& r) {
	return l.id() < r.id();
}

certificate_revocation revoke_certificate(private_key const& key, certificate cert) {
	if(key.id() != cert.issuer()) {
		LOG_WARN("private key does not match the issuer of the certificate");
		throw error(errc::invalid_public_key);
	}
	certificate_revocation rev(cert.id());
	rev.sign_me(key);
	return rev;
}

}
