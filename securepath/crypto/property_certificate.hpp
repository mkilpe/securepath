// SPDX-License-Identifier: MIT

#pragma once

#include "certificate.hpp"
#include "types.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/types.hpp>

#include <string>

namespace securepath::crypto {

namespace property {
	struct info {
		std::string type;
		std::string info;

		template<typename Ar>
		void serialise(Ar& ar) {
			serialisation::sequence<Ar> seq(ar, 1);
			seq & type & info;
		}
	};
}

/// Certificate data carrying an arbitrary typed property of the issuer
class property_certificate_data {
public:
	enum {id = 3}; //certificate type id

	property_certificate_data() = default;
	property_certificate_data(property::info const& info)
	: data_(serialisation::asn_der_serialise(info))
	{}

	property::info info() const {
		return serialisation::asn_der_deserialise<property::info>(data_);
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version_ & data_;
	}

private:
	int version_{1};
	octet_vector data_;
};

class private_key;

inline
certificate create_property_certificate(private_key const& key, std::string const& type, std::string const& info) {
	certificate cert(property_certificate_data::id, serialisation::asn_der_serialise(property_certificate_data({type, info})));
	cert.sign_me(key);
	return cert;
}

}
