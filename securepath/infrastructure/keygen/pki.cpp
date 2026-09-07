// SPDX-License-Identifier: MIT

#include "pki.hpp"

#include <securepath/crypto/key_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_database.hpp>
#include <securepath/crypto/public_key_database.hpp>
#include <securepath/crypto/root_public_key.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>

#include <fstream>
#include <stdexcept>

namespace securepath::keygen {

namespace fs = std::filesystem;

namespace {

template<typename T>
T load_der(fs::path const& path) {
	std::ifstream in(path, std::ios::binary);
	if(!in) {
		throw std::runtime_error("cannot read " + path.string());
	}
	return serialisation::asn_der_deserialise<T>(in);
}

template<typename T>
void save_der(fs::path const& path, T& value) {
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	if(!out) {
		throw std::runtime_error("cannot write " + path.string());
	}
	serialisation::asn_der_serialise(out, value);
	if(!out) {
		throw std::runtime_error("failed to write " + path.string());
	}
}

/// certify subject with issuer and attach the certificate id to the subject's public half
crypto::certificate certify_key(crypto::private_key const& issuer, crypto::private_key& subject,
	std::uint16_t ca_level, crypto::key_cert_restriction const& rest)
{
	auto pub = subject.public_key();
	auto cert = crypto::create_key_certificate(issuer, pub.id(), ca_level, rest);
	pub.add_certificate_id(cert.id());
	subject.set_public_key(pub);
	return cert;
}

/// private material is for the owner only
void restrict_to_owner(fs::path const& path) {
	fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
}

void ensure_parent_directory(std::string const& file) {
	auto parent = fs::path(file).parent_path();
	if(!parent.empty()) {
		fs::create_directories(parent);
	}
}

}

pki::pki(fs::path dir)
: dir_(std::move(dir))
{
}

bool pki::exists() const {
	return fs::exists(root_private_key_file());
}

void pki::create(crypto::suite s) {
	if(exists()) {
		throw std::runtime_error("a pki already exists in " + dir_.string());
	}
	fs::create_directories(dir_);
	root_ = crypto::generate_private_key(s);
	ca_ = crypto::generate_private_key(s);
	ca_cert_ = certify_key(root_, ca_, 1, {});
	write_files();
	install();
	LOG_INFO("created pki in {} (root {}, ca {})", dir_.string(), root_.id(), ca_.id());
}

void pki::load() {
	root_ = load_der<crypto::private_key>(root_private_key_file());
	ca_ = load_der<crypto::private_key>(ca_private_key_file());
	ca_cert_ = load_der<crypto::certificate>(ca_certificate_file());
	if(ca_cert_.issuer() != root_.id()) {
		throw std::runtime_error("the CA certificate in " + dir_.string() + " is not issued by the root key");
	}
	install();
}

void pki::write_files() {
	save_der(root_private_key_file(), root_);
	restrict_to_owner(root_private_key_file());
	crypto::save_public_key_file(root_public_key_file().string(), root_.public_key());
	save_der(ca_private_key_file(), ca_);
	restrict_to_owner(ca_private_key_file());
	save_der(ca_certificate_file(), ca_cert_);
}

void pki::install() {
	crypto::set_root_public_key(root_.public_key());
	ca_chain_ = crypto::certificate_chain(root_.id(), {{ca_.public_key(), ca_cert_}});
}

crypto::certificate_chain pki::certify(crypto::private_key& key, std::string const& host) const {
	auto cert = certify_key(ca_, key, 0, crypto::key_cert_restriction().hostname(host));
	crypto::certificate_chain chain{ca_chain_};
	chain.add_link(key.public_key(), cert);
	return chain;
}

crypto::private_key install_identity(pki const& p, identity_stores const& stores, std::string const& host) {
	ensure_parent_directory(stores.private_data_db);
	ensure_parent_directory(stores.public_key_db);
	crypto::private_data_database priv(database::sqlite::create_sqlite_connection(stores.private_data_db));
	if(priv.my_private_key()) {
		throw std::runtime_error("an own private key already exists in " + stores.private_data_db);
	}
	auto key = crypto::generate_private_key(p.ca().suite());
	auto chain = p.certify(key, host);
	priv.set_my_private_key(key);
	priv.set_my_certificate_chain(chain);
	restrict_to_owner(stores.private_data_db);
	crypto::public_key_database pub(database::sqlite::create_sqlite_connection(stores.public_key_db));
	pub.insert(key.public_key());
	LOG_INFO("installed identity {} into {}", key.id(), stores.private_data_db);
	return key;
}

}
