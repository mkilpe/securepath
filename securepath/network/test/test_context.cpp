// SPDX-License-Identifier: MIT

#include "network_test_context.hpp"

#include <securepath/network/encryption/error.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/util/error.hpp>

namespace securepath::network::test {

TEST_CASE("context handshake registry", "[network][context]") {
	network_test_context tc;
	auto& server = tc.server_context();
	CHECK_THROWS_AS(server.construct_handshake(handshake_data{handshake_tag::public_key}), securepath::error);
	tc.setup_pk_server();
	// binding is empty here, construct_handshake still returns a handshake object for a known tag
	CHECK(server.construct_handshake(handshake_data{handshake_tag::public_key}));
	CHECK(server.suite() == crypto::default_suite());
	CHECK(server.tls_group() == Botan::TLS::Group_Params(Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768));
}

TEST_CASE("context suite selects the tls group", "[network][context]") {
	network_test_context tc{crypto::suite::pq1_high};
	CHECK(tc.server_context().suite() == crypto::suite::pq1_high);
	CHECK(tc.server_context().tls_group()
		== Botan::TLS::Group_Params(Botan::TLS::Group_Params::HYBRID_SECP384R1_ML_KEM_1024));
}

}
