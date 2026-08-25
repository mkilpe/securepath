// SPDX-License-Identifier: MIT

#include "private_key_impl.hpp"
#include "public_key_impl.hpp"
#include "rng.hpp"
#include "secure.hpp"
#include "suite_parameters.hpp"

#include <securepath/serialisation/map.hpp>

#include <botan/exceptn.h>
#include <botan/ml_dsa.h>
#include <botan/pubkey.h>

namespace securepath::crypto {
namespace {

public_key make_public_key(suite s, Botan::secure_vector<std::uint8_t> const& sig_seed, detail::kem_private_key const& kem) {
	auto const& p = detail::parameters(s);
	if(sig_seed.size() != p.sig_seed_size) {
		throw invalid_key("signing key seed does not match the suite");
	}
	try {
		Botan::ML_DSA_PrivateKey sk(sig_seed, Botan::ML_DSA_Mode(p.sig_mode));
		detail::kem_public_key kem_pk = detail::kem_public_part(kem);
		return public_key(std::make_shared<public_key_impl>(s, sk.public_key_bits(), std::move(kem_pk.x_pk), std::move(kem_pk.pq_pk)));
	} catch(Botan::Exception const& e) {
		throw invalid_key(std::string("invalid private key material: ") + e.what());
	}
}

}

private_key_impl::private_key_impl(suite s, Botan::secure_vector<std::uint8_t> sig_seed, detail::kem_private_key kem)
: suite_(s)
, public_key_(make_public_key(s, sig_seed, kem))
, sig_seed_(std::move(sig_seed))
, kem_x_sk_(std::move(kem.x_sk))
, kem_pq_seed_(std::move(kem.pq_seed))
{
}

bool private_key_impl::is_valid() const {
	auto const& p = detail::parameters(suite_);
	return sig_seed_.size() == p.sig_seed_size && kem_x_sk_.size() == p.x_key_size && kem_pq_seed_.size() == p.kem_seed_size
		&& public_key_.is_valid() && public_key_.suite() == suite_;
}

octet_vector private_key_impl::sign_framed(octet_span framed) const {
	if(!is_valid()) {
		throw invalid_key("cannot sign with an empty private key");
	}
	Botan::ML_DSA_PrivateKey sk(sig_seed_, Botan::ML_DSA_Mode(detail::parameters(suite_).sig_mode));
	Botan::PK_Signer signer(sk, detail::rng(), "Randomized");
	return signer.sign_message(framed.data(), framed.size(), detail::rng());
}

Botan::secure_vector<std::uint8_t> private_key_impl::decapsulate(octet_span ct_x, octet_span ct_pq) const {
	if(!is_valid()) {
		throw invalid_key("cannot decrypt with an empty private key");
	}
	detail::kem_private_key kem{suite_, kem_x_sk_, kem_pq_seed_};
	return detail::kem_decapsulate(kem, ct_x, ct_pq);
}

void private_key_impl::serialise(serialisation::serialiser& s) {
	octet_vector sig_seed = detail::to_octets(sig_seed_);
	octet_vector kem_x_sk = detail::to_octets(kem_x_sk_);
	octet_vector kem_pq_seed = detail::to_octets(kem_pq_seed_);
	{
		serialisation::sequence seq(s);
		seq & version_ & suite_ & public_key_ & sig_seed & kem_x_sk & kem_pq_seed & metadata_ & trailing_;
	}
	detail::scrub(sig_seed);
	detail::scrub(kem_x_sk);
	detail::scrub(kem_pq_seed);
}

void private_key_impl::serialise(serialisation::deserialiser& s) {
	octet_vector sig_seed;
	octet_vector kem_x_sk;
	octet_vector kem_pq_seed;
	{
		serialisation::sequence seq(s);
		seq & version_ & suite_ & public_key_ & sig_seed & kem_x_sk & kem_pq_seed & metadata_ & trailing_;
	}
	sig_seed_ = detail::to_secure(sig_seed);
	kem_x_sk_ = detail::to_secure(kem_x_sk);
	kem_pq_seed_ = detail::to_secure(kem_pq_seed);
}

}
