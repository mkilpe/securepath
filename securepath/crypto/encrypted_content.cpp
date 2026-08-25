// SPDX-License-Identifier: MIT

#include "encrypted_content.hpp"

#include "aes_gcm.hpp"
#include "random.hpp"
#include "types.hpp"

namespace securepath::crypto {

encrypted_content::encrypted_content(octet_vector data, octet_vector iv, octet_vector tag)
: iv_(std::move(iv))
, encrypted_(std::move(data))
, tag_(std::move(tag))
{}

bool encrypted_content::empty() const {
	return encrypted_.empty();
}

octet_vector const& encrypted_content::iv() const {
	return iv_;
}

octet_vector const& encrypted_content::content() const {
	return encrypted_;
}

octet_vector const& encrypted_content::tag() const {
	return tag_;
}

encrypted_content encrypt(octet_vector const& data, octet_vector const& sym_key) {
	octet_vector iv = random_octet_vector(aes_gcm_iv_size());
	auto enc = create_aes_gcm_stream_encryptor(sym_key, iv);

	enc->process_auth(iv);
	octet_vector encdata = enc->process(data);

	return encrypted_content(std::move(encdata), std::move(iv), enc->tag());
}

octet_vector decrypt(encrypted_content const& ec, octet_vector const& sym_key) {
	auto dec = create_aes_gcm_stream_decryptor(sym_key, ec.iv());

	dec->process_auth(ec.iv());
	octet_vector result = dec->process(ec.content());

	if(!tag_matches(dec->tag(), ec.tag())) {
		throw invalid_tag();
	}

	return result;
}

}
