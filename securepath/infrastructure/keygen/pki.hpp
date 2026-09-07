// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/certificate_chain.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/suite.hpp>

#include <filesystem>
#include <string>

namespace securepath::keygen {

/**
 * The key material of a deployment: a root key, a CA key certified by the root (ca level 1)
 * and the means to certify server and client keys with the CA. Kept as DER files in one
 * directory:
 *   root.priv  root private key, only needed to create the CA (keep it offline)
 *   root.pub   root public key, the trust anchor every process loads with --root
 *   ca.priv    CA private key that certifies the server and client keys
 *   ca.cert    the CA's key certificate issued by the root
 * The private keys are stored unencrypted (owner-only file permissions); protect the directory.
 * create() and load() install the root as the process-wide root public key.
 */
class pki {
public:
	explicit pki(std::filesystem::path dir);

	/// true when the directory already holds a root private key
	bool exists() const;
	/// create a new root and CA into the directory, throws when a pki already exists there
	void create(crypto::suite = crypto::default_suite());
	/// load the material from the directory, throws when a file is missing, malformed or the CA is not from the root
	void load();

	/// certify the key with the CA (ca level 0, optional hostname restriction); attaches the
	/// certificate id to the key's public half and returns the root -> CA -> key chain
	crypto::certificate_chain certify(crypto::private_key& key, std::string const& host = {}) const;

	crypto::private_key const& root() const { return root_; }
	crypto::private_key const& ca() const { return ca_; }
	/// root -> CA chain that every certified chain starts with
	crypto::certificate_chain const& ca_chain() const { return ca_chain_; }

	std::filesystem::path root_private_key_file() const { return dir_ / "root.priv"; }
	std::filesystem::path root_public_key_file() const { return dir_ / "root.pub"; }
	std::filesystem::path ca_private_key_file() const { return dir_ / "ca.priv"; }
	std::filesystem::path ca_certificate_file() const { return dir_ / "ca.cert"; }

private:
	void write_files();
	void install();

private:
	std::filesystem::path dir_;
	crypto::private_key root_;
	crypto::private_key ca_;
	crypto::certificate ca_cert_;
	crypto::certificate_chain ca_chain_;
};

/// the stores an identity is installed into; both may name the same sqlite file
struct identity_stores {
	/// private data database receiving the private key and its chain (my_private_key / my_certificate_chain)
	std::string private_data_db;
	/// public key database receiving the public half
	std::string public_key_db;
};

/**
 * Generate a key of the pki's suite, certify it (optional hostname restriction) and store it as
 * the own identity of the given stores, creating the databases and their directories as needed.
 * Throws when the private data store already holds an own key. Returns the new key.
 */
crypto::private_key install_identity(pki const&, identity_stores const&, std::string const& host = {});

}
