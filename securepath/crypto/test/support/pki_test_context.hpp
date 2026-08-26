// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/certificate_chain.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/suite.hpp>

#include <optional>
#include <string>

namespace securepath::crypto::test {

/**
 * Small PKI for tests: a root key, a CA key certified by the root (ca level 1) and helpers to
 * certify further keys. The constructor installs the root as the process-wide root public key
 * (set_root_public_key); the destructor restores whatever root was set before.
 */
struct pki_test_context {
	pki_test_context();
	explicit pki_test_context(crypto::private_key root);
	explicit pki_test_context(suite s);
	~pki_test_context();

	pki_test_context(pki_test_context const&) = delete;
	pki_test_context& operator=(pki_test_context const&) = delete;

	/// certify the key with the CA (ca level 0, optional hostname restriction) and return root -> ca -> key chain
	certificate_chain chain_for_server_key(private_key& server_key, std::string const& host = "");

	crypto::private_key root;
	crypto::private_key ca_key;
	crypto::certificate_chain ca_chain;
	/// empty by default; tests that exercise revocation insert the revoked certificate here
	/// so chain validation (which consults this store) rejects it
	crypto::certificate_cache certs;

private:
	std::optional<public_key> previous_root_;
};

}
