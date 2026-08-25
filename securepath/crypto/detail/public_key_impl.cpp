// SPDX-License-Identifier: MIT

#include "public_key_impl.hpp"
#include "suite_parameters.hpp"
#include "../hash.hpp"

#include <securepath/serialisation/set.hpp>
#include <securepath/serialisation/util.hpp>

#include <botan/exceptn.h>
#include <botan/ml_dsa.h>
#include <botan/pubkey.h>

namespace securepath::crypto {
namespace {

struct id_content {
	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & s & sig_pk & kem_x_pk & kem_pq_pk;
	}
	suite s{};
	octet_vector sig_pk;
	octet_vector kem_x_pk;
	octet_vector kem_pq_pk;
};

}

public_key_impl::public_key_impl(suite s, octet_vector sig_pk, octet_vector kem_x_pk, octet_vector kem_pq_pk)
: suite_(s)
, sig_pk_(std::move(sig_pk))
, kem_x_pk_(std::move(kem_x_pk))
, kem_pq_pk_(std::move(kem_pq_pk))
, id_(construct_id())
{
}

bool public_key_impl::is_valid() const {
	auto const& p = detail::parameters(suite_);
	return sig_pk_.size() == p.sig_public_size && kem_x_pk_.size() == p.x_key_size && kem_pq_pk_.size() == p.kem_public_size;
}

public_key_id public_key_impl::construct_id() const {
	octet_vector vec = serialisation::asn_der_serialise(id_content{suite_, sig_pk_, kem_x_pk_, kem_pq_pk_});
	return public_key_id(hash(vec, hash_algorithm::sha3_256));
}

octet_vector public_key_impl::signature_content() const {
	octet_vector vec;
	{
		serialisation::octet_vector_ostream ss(vec);
		auto ser = serialisation::make_serialiser<serialisation::asn_der_encoder<serialisation::octet_vector_ostream>>(ss);
		serialisation::sequence seq(ser);
		seq & version_ & suite_ & sig_pk_ & kem_x_pk_ & kem_pq_pk_ & certificate_ids_ & trailing_;
	}
	return vec;
}

bool public_key_impl::verify_framed(octet_span framed, octet_span sig) const {
	bool ret = false;
	if(is_valid()) {
		try {
			Botan::ML_DSA_PublicKey key(sig_pk_, Botan::ML_DSA_Mode(detail::parameters(suite_).sig_mode));
			Botan::PK_Verifier verifier(key, "");
			ret = verifier.verify_message(framed.data(), framed.size(), sig.data(), sig.size());
		} catch(Botan::Exception const&) {
			ret = false;
		}
	}
	return ret;
}

void public_key_impl::serialise(serialisation::serialiser& s) {
	serialisation::sequence seq(s);
	seq & version_ & suite_ & sig_pk_ & kem_x_pk_ & kem_pq_pk_ & certificate_ids_ & sig_ & trailing_;
}

void public_key_impl::serialise(serialisation::deserialiser& s) {
	{
		serialisation::sequence seq(s);
		seq & version_ & suite_ & sig_pk_ & kem_x_pk_ & kem_pq_pk_ & certificate_ids_ & sig_ & trailing_;
	}
	id_ = construct_id();
}

}
