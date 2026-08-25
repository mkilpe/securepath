// SPDX-License-Identifier: MIT

#pragma once

#include "certificate.hpp"
#include "types.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>

#include <string>

namespace securepath::crypto {

/// Certificate data binding a human readable identifier to the issuer
class identifier_certificate_data {
public:
	enum {id = 2}; //certificate type id

	identifier_certificate_data() = default;
	identifier_certificate_data(std::string const& id)
	: identifier_(id)
	{}

	std::string identifier() const { return identifier_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & identifier_;
	}

private:
	int version_{1};
	std::string identifier_;
};

class private_key;

inline
certificate create_identifier_certificate(private_key const& key, std::string const& identifier) {
	certificate cert(identifier_certificate_data::id, serialisation::asn_der_serialise(identifier_certificate_data(identifier)));
	cert.sign_me(key);
	return cert;
}

}
