// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/identifier_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

TEST_CASE("identifier_certificate basic test", "[identifier_certificate][certificate_data]") {
	std::string const id = random_string(16);
	identifier_certificate_data ic(id);
	CHECK(ic.identifier() == id);
	auto ser = serialisation::asn_der_serialise(ic);
	identifier_certificate_data res = serialisation::asn_der_deserialise<identifier_certificate_data>(ser);
	CHECK(res.identifier() == ic.identifier());
	CHECK(res.id == ic.id);
}

TEST_CASE("identifier_certificate create", "[identifier_certificate][certificate_data]") {
	auto key = generate_private_key();
	std::string const i = "id1";
	certificate cert = create_identifier_certificate(key, i);
	REQUIRE(cert.type() == identifier_certificate_data::id);
	CHECK(cert.is_authentic(key.public_key()));
	auto res = cert.extract<identifier_certificate_data>();
	CHECK(res.identifier() == i);
}

}
