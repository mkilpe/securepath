// SPDX-License-Identifier: MIT

#include "pki_test_context.hpp"

#include <securepath/crypto/key_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/root_public_key.hpp>

namespace securepath::crypto::test {

pki_test_context::pki_test_context()
: pki_test_context(crypto::generate_private_key())
{
}

pki_test_context::pki_test_context(suite s)
: pki_test_context(crypto::generate_private_key(s))
{
}

pki_test_context::pki_test_context(crypto::private_key r)
: root(std::move(r))
, ca_key(crypto::generate_private_key(root.suite()))
{
	if(has_root_public_key()) {
		previous_root_ = root_public_key();
	}
	set_root_public_key(root.public_key());

	auto pkey = ca_key.public_key();
	auto cert = create_key_certificate(root, pkey, 1);
	pkey.add_certificate_id(cert.id());
	ca_key.set_public_key(pkey);
	ca_chain = certificate_chain(root.id(), {{ca_key.public_key(), cert}});
}

pki_test_context::~pki_test_context() {
	if(previous_root_) {
		set_root_public_key(*previous_root_);
	} else {
		clear_root_public_key();
	}
}

certificate_chain pki_test_context::chain_for_server_key(private_key& server_key, std::string const& host) {
	auto pkey = server_key.public_key();
	auto cert = create_key_certificate(ca_key, pkey, 0, key_cert_restriction().hostname(host));
	pkey.add_certificate_id(cert.id());
	server_key.set_public_key(pkey);
	certificate_chain copy{ca_chain};
	copy.add_link(server_key.public_key(), cert);
	return copy;
}

}
