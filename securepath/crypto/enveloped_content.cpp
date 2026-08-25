// SPDX-License-Identifier: MIT

#include "enveloped_content.hpp"

#include "aes_gcm.hpp"
#include "private_key.hpp"
#include "random.hpp"

#include <securepath/log/log.hpp>

namespace securepath::crypto {

enveloped_content::enveloped_content(std::deque<encrypted_key> keys, octet_vector data, octet_vector iv, octet_vector tag)
: keys_(std::move(keys))
, iv_(std::move(iv))
, encrypted_(std::move(data))
, tag_(std::move(tag))
{}

bool enveloped_content::empty() const {
	return encrypted_.empty();
}

octet_vector enveloped_content::decrypt(private_key const& key) const {
	auto it = keys_.begin();
	for(; it != keys_.end() && it->key_id() != key.id(); ++it) {}
	if(it == keys_.end()) {
		LOG_WARN("wrong key for decrypting enveloped_content [key={}]", key.id());
		throw wrong_key();
	}

	octet_vector sym_key = decrypt_key(key, *it);
	auto dec = create_aes_gcm_stream_decryptor(sym_key, iv_);

	dec->process_auth(iv_);
	octet_vector result = dec->process(encrypted_);

	if(!tag_matches(dec->tag(), tag_)) {
		LOG_WARN("invalid tag with enveloped_content");
		throw invalid_tag();
	}

	return result;
}

void enveloped_content::add(encrypted_key key) {
	keys_.push_back(std::move(key));
}

enveloper::enveloper(octet_vector data)
: data_(std::move(data))
, sym_key_(random_octet_vector(aes_gcm_key_size()))
{
}

void enveloper::add(public_key const& pk) {
	keys_.push_back(encrypt_key(pk));
}

encrypted_key enveloper::encrypt_key(public_key const& pk) const {
	return crypto::encrypt_key(pk, sym_key_);
}

enveloped_content enveloper::result() const {
	octet_vector iv = random_octet_vector(aes_gcm_iv_size());
	auto enc = create_aes_gcm_stream_encryptor(sym_key_, iv);

	enc->process_auth(iv);
	octet_vector encdata = enc->process(data_);

	return enveloped_content(keys_, std::move(encdata), std::move(iv), enc->tag());
}

enveloped_content envelope(public_key const& key, octet_vector const& data) {
	std::deque<public_key> k = {key};
	return envelope(k, data);
}

enveloped_content envelope(std::deque<public_key> const& keys, octet_vector const& data) {
	enveloper env(data);
	for(auto&& v : keys) {
		env.add(v);
	}
	return env.result();
}

octet_vector decrypt(enveloped_content const& en, private_key const& key) {
	return en.decrypt(key);
}

}
