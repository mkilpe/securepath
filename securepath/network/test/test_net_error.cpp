// SPDX-License-Identifier: MIT

#include <securepath/network/net_error.hpp>
#include <securepath/network/encryption/error.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <sstream>

namespace securepath::network::test {

TEST_CASE("network error codes have messages", "[network][error]") {
	std::error_code ec = make_error_code(errc::tls_failure);
	CHECK(ec);
	CHECK(ec == make_error_code(errc::tls_failure));
	CHECK(ec.message() == "TLS failure");
	CHECK(make_error_code(errc::handshake_failed).message() == "Handshake failed");
	CHECK(std::string(ec.category().name()) == "securepath network error");
}

TEST_CASE("net_error transfers an error", "[network][error]") {
	net_error none;
	CHECK_FALSE(none);

	securepath::error err(make_error_code(errc::authentication_failure), "bad key");
	net_error ne(err);
	CHECK(ne);
	CHECK(ne.code() == static_cast<int>(errc::authentication_failure));
	CHECK(ne.message() == "Authentication failed");
	CHECK(ne.aux_message() == "bad key");

	octet_vector wire = serialisation::asn_der_serialise(ne);
	auto back = serialisation::asn_der_deserialise<net_error>(wire);
	CHECK(back.code() == ne.code());
	CHECK(back.category() == ne.category());
	CHECK(back.message() == ne.message());
	CHECK(back.aux_message() == ne.aux_message());

	std::ostringstream out;
	out << back;
	CHECK(out.str().find("Authentication failed") != std::string::npos);
	std::ostringstream out2;
	out2 << none;
	CHECK(out2.str() == "no error");
}

}
