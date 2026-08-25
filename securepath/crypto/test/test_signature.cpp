// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/crypto/signature.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::crypto::test {

TEST_CASE("signature basic test", "[signature]") {
	auto const priv_key = generate_private_key();
	octet_vector data = random_octet_vector(16);

	signature sig(priv_key.id(), data);
	CHECK(sig.is_valid());
	CHECK(!signature().is_valid());

	octet_vector ser = serialisation::asn_der_serialise(sig);
	signature res = serialisation::asn_der_deserialise<signature>(ser);

	CHECK(res == sig);
	CHECK(res.issuer() == sig.issuer());
	CHECK(res.issuer() == priv_key.id());
	CHECK(res.data() == sig.data());
	CHECK(res.data() == data);
	CHECK(res != signature(priv_key.id(), random_octet_vector(16)));
}

TEST_CASE("signature round trip through serialisation verifies", "[signature][serialisation]") {
	auto const priv_key = generate_private_key();
	octet_vector data = random_octet_vector(100);
	signature sig = priv_key.sign(data);

	octet_vector ser = serialisation::asn_der_serialise(sig);
	signature res = serialisation::asn_der_deserialise<signature>(ser);
	CHECK(priv_key.public_key().verify(res, data));
}

}
