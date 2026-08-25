// SPDX-License-Identifier: MIT

#include "public_key.hpp"

#include "aes_gcm.hpp"
#include "certificate_id.hpp"
#include "private_key.hpp"
#include "random.hpp"
#include "signature.hpp"
#include "detail/framing.hpp"
#include "detail/hybrid_kem.hpp"
#include "detail/public_key_impl.hpp"

#include <securepath/serialisation/util.hpp>

#include <botan/aead.h>

namespace securepath::crypto {

namespace {

std::string_view const self_signature_context = "sp-key";

}

public_key::public_key()
: impl_(std::make_shared<public_key_impl>())
{}

public_key::public_key(std::shared_ptr<public_key_impl> p)
: impl_(std::move(p))
{}

public_key_id public_key::id() const {
	return impl_->id_;
}

crypto::suite public_key::suite() const {
	return impl_->suite_;
}

bool public_key::is_valid() const {
	return impl_->is_valid();
}

octet_vector public_key::encrypt(octet_vector const& plain) const {
	if(!is_valid()) {
		throw invalid_key("cannot encrypt with an empty public key");
	}
	detail::kem_public_key kem{impl_->suite_, impl_->kem_x_pk_, impl_->kem_pq_pk_};
	detail::kem_encapsulation enc = detail::kem_encapsulate(kem);

	detail::hybrid_ciphertext ct;
	ct.id = impl_->suite_;
	ct.ct_x = std::move(enc.ct_x);
	ct.ct_pq = std::move(enc.ct_pq);
	ct.iv = random_octet_vector(aes_gcm_iv_size());

	auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
	aead->set_key(enc.key);
	aead->set_associated_data(impl_->id_.data());
	aead->start(ct.iv);
	Botan::secure_vector<std::uint8_t> buf(plain.begin(), plain.end());
	aead->finish(buf);

	std::size_t const tag = aes_gcm_tag_size();
	ct.encrypted.assign(buf.begin(), buf.end() - tag);
	ct.tag.assign(buf.end() - tag, buf.end());
	return serialisation::asn_der_serialise(ct);
}

bool public_key::verify(signature const& sig, octet_vector const& data, std::string_view context) const {
	return impl_->verify_framed(detail::frame_message(context, data), sig.data());
}

void public_key::serialise(serialisation::serialiser& s) {
	impl_->serialise(s);
}

void public_key::serialise(serialisation::deserialiser& s) {
	impl_->serialise(s);
}

void public_key::sign_me(private_key const& key) {
	impl_->sig_ = key.sign(impl_->signature_content(), self_signature_context);
}

bool public_key::verify_me() const {
	return verify(impl_->sig_, impl_->signature_content(), self_signature_context) && impl_->construct_id() == impl_->id_;
}

void public_key::add_certificate_id(certificate_id id) {
	impl_->certificate_ids_.insert(std::move(id));
}

void public_key::remove_certificate_id(certificate_id id) {
	impl_->certificate_ids_.erase(id);
}

std::set<certificate_id> public_key::get_cert_ids() const {
	return impl_->certificate_ids_;
}

bool public_key::references_certificate(certificate_id const& id) const {
	return impl_->certificate_ids_.find(id) != impl_->certificate_ids_.end();
}

}
