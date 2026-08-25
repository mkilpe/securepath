// SPDX-License-Identifier: MIT

#include "hmac.hpp"

#include <botan/mac.h>

namespace securepath::crypto {
namespace {

class hmac : public mac {
public:
	hmac(hash_algorithm id, octet_span key)
	: mac_(Botan::MessageAuthenticationCode::create_or_throw("HMAC(" + detail::botan_hash_name(id) + ")"))
	{
		mac_->set_key(key.data(), key.size());
	}

	std::size_t size() const override {
		return mac_->output_length();
	}

	std::size_t calculate(std::uint8_t const* begin, std::uint8_t const* end, std::uint8_t* out) override {
		mac_->update(begin, static_cast<std::size_t>(end-begin));
		mac_->final(out);
		return size();
	}

	bool verify(std::uint8_t const* begin, std::uint8_t const* end, std::uint8_t const* mac) override {
		mac_->update(begin, static_cast<std::size_t>(end-begin));
		return mac_->verify_mac(mac, size());
	}

private:
	std::unique_ptr<Botan::MessageAuthenticationCode> mac_;
};

}

mac_ptr create_hmac_sha256(octet_span key) {
	return create_hmac(hash_algorithm::sha256, key);
}

mac_ptr create_hmac(hash_algorithm id, octet_span key) {
	return std::make_unique<hmac>(id, key);
}

}
