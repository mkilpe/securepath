// SPDX-License-Identifier: MIT

#include "private_key.hpp"

#include "aes_gcm.hpp"
#include "signature.hpp"
#include "detail/framing.hpp"
#include "detail/hybrid_kem.hpp"
#include "detail/private_key_impl.hpp"

#include <securepath/serialisation/util.hpp>

#include <botan/aead.h>
#include <botan/exceptn.h>

namespace securepath::crypto {

namespace {

detail::hybrid_ciphertext parse_ciphertext(octet_vector const& cipher, suite expected) {
	detail::hybrid_ciphertext ct;
	try {
		ct = serialisation::asn_der_deserialise<detail::hybrid_ciphertext>(cipher);
	} catch(std::exception const& e) {
		throw bad_ciphertext(std::string("malformed ciphertext: ") + e.what());
	}
	if(ct.version != 1) {
		throw bad_ciphertext("unsupported ciphertext version");
	}
	if(ct.id != expected) {
		throw bad_ciphertext("ciphertext suite does not match the key");
	}
	if(ct.iv.size() != aes_gcm_iv_size() || ct.tag.size() != aes_gcm_tag_size()) {
		throw bad_ciphertext("malformed ciphertext: iv or tag size");
	}
	return ct;
}

octet_vector open(Botan::secure_vector<std::uint8_t> const& key, public_key_id const& id, detail::hybrid_ciphertext const& ct) {
	auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
	aead->set_key(key);
	aead->set_associated_data(id.data());
	aead->start(ct.iv);
	Botan::secure_vector<std::uint8_t> buf(ct.encrypted.begin(), ct.encrypted.end());
	buf.insert(buf.end(), ct.tag.begin(), ct.tag.end());
	try {
		aead->finish(buf);
	} catch(Botan::Invalid_Authentication_Tag const&) {
		throw bad_ciphertext("authentication failed");
	}
	return octet_vector(buf.begin(), buf.end());
}

}

private_key::private_key()
: impl_(std::make_shared<private_key_impl>())
{}

private_key::private_key(std::shared_ptr<private_key_impl> p)
: impl_(std::move(p))
{
	impl_->public_key_.sign_me(*this);
}

void private_key::serialise(serialisation::serialiser& s) {
	impl_->serialise(s);
}

void private_key::serialise(serialisation::deserialiser& s) {
	impl_->serialise(s);
}

public_key_id private_key::id() const {
	return impl_->public_key_.id();
}

crypto::suite private_key::suite() const {
	return impl_->suite_;
}

crypto::public_key private_key::public_key() const {
	return impl_->public_key_;
}

bool private_key::is_valid() const {
	return impl_->is_valid();
}

void private_key::set_public_key(crypto::public_key key) {
	if(key.id() != id()) {
		throw invalid_key("invalid public key, id does not match with the private key");
	}
	key.sign_me(*this);
	impl_->public_key_ = std::move(key);
}

signature private_key::sign(octet_vector const& data, std::string_view context) const {
	return signature{id(), impl_->sign_framed(detail::frame_message(context, data))};
}

octet_vector private_key::decrypt(octet_vector const& cipher) const {
	detail::hybrid_ciphertext ct = parse_ciphertext(cipher, impl_->suite_);
	auto key = impl_->decapsulate(ct.ct_x, ct.ct_pq);
	return open(key, id(), ct);
}

void private_key::metadata(std::string const& key, octet_vector data) {
	if(data.empty()) {
		impl_->metadata_.erase(key);
	} else {
		impl_->metadata_[key] = std::move(data);
	}
}

octet_vector private_key::metadata(std::string const& key) const {
	auto it = impl_->metadata_.find(key);
	return it != impl_->metadata_.end() ? it->second : octet_vector();
}

}
