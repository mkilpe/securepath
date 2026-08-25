// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/property_certificate.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

TEST_CASE("property_certificate basic test", "[property_certificate][certificate_data]") {
	property::info info{"type", "info"};
	property_certificate_data prop(info);
	auto ser = serialisation::asn_der_serialise(prop);
	property_certificate_data res = serialisation::asn_der_deserialise<property_certificate_data>(ser);
	CHECK(prop.id == res.id);
	property::info info1 = prop.info();
	property::info info2 = res.info();
	REQUIRE(info1.type == "type");
	REQUIRE(info1.info == "info");
	CHECK(info.type == info2.type);
	CHECK(info.info == info2.info);
}

TEST_CASE("property_certificate create", "[property_certificate][certificate_data]") {
	auto key = generate_private_key();
	std::string const type = "type1";
	std::string const info = "info1";
	certificate cert = create_property_certificate(key, type, info);
	REQUIRE(cert.type() == property_certificate_data::id);
	CHECK(cert.is_authentic(key.public_key()));
	auto res = cert.extract<property_certificate_data>();
	property::info prop_info = res.info();
	CHECK(prop_info.type == type);
	CHECK(prop_info.info == info);
}

}
