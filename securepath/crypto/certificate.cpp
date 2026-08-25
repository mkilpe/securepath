// SPDX-License-Identifier: MIT

#include "certificate.hpp"

#include "hash.hpp"
#include "private_key.hpp"
#include "public_key.hpp"

#include <securepath/serialisation/util.hpp>

#include <cassert>

namespace securepath::crypto {

namespace {
std::string_view const certificate_context = "sp-cert";
}

octet_vector certificate::make_sig_data() const {
	using namespace serialisation;
	octet_vector v;
	octet_vector_ostream ss(v);
	auto ser = make_serialiser<asn_der_encoder<octet_vector_ostream>>(ss);
	sequence<serialiser> seq(ser);
	seq & version_ & certificate_type_ & certificate_data_ & trailing_;
	return v;
}

bool certificate::is_authentic(public_key const& key) const {
	return verify_me(key) && !revocation_;
}

void certificate::sign_me(private_key const& key) {
	sig_ = key.sign(make_sig_data(), certificate_context);
}

bool certificate::verify_me(public_key const& key) const {
	return key.verify(sig_, make_sig_data(), certificate_context)
		&& (!revocation_ || revocation_->verify_me(key));
}

certificate_id certificate::id() const {
	assert(sig_.is_valid());
	octet_vector ser = serialisation::asn_der_serialise(sig_);
	return certificate_id(crypto::hash(ser, hash_algorithm::sha3_256));
}

bool operator==(certificate const& l, certificate const& r) {
	return l.id() == r.id();
}

bool operator!=(certificate const& l, certificate const& r) {
	return !(l == r);
}

bool operator<(certificate const& l, certificate const& r) {
	return l.id() < r.id();
}

}
