// SPDX-License-Identifier: MIT

#include <securepath/infrastructure/keygen/pki.hpp>

#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/key_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_database.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/public_key_database.hpp>
#include <securepath/crypto/root_public_key.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <filesystem>
#include <random>
#include <string>

namespace securepath::keygen::test {

namespace {

namespace fs = std::filesystem;

std::string unique_suffix() {
	std::random_device rd;
	return std::to_string(rd()) + "_" + std::to_string(rd());
}

/// a fresh directory under the system temp directory, removed at the end of the test; the
/// process-wide root the pki installs is cleared as well
struct fixture {
	fixture()
	: dir(fs::temp_directory_path() / fs::path("sp_keygen_test_" + unique_suffix()))
	{
		fs::create_directories(dir);
	}

	~fixture() {
		crypto::clear_root_public_key();
		std::error_code ec;
		fs::remove_all(dir, ec);
	}

	std::string file(std::string const& name) const {
		return (dir / name).string();
	}

	fs::path dir;
	/// plain caches: the root comes from the process-wide root public key, no revocations
	crypto::public_key_cache keys;
	crypto::certificate_cache certs;
};

}

TEST_CASE_METHOD(fixture, "keygen pki create writes the material and installs the root", "[keygen]") {
	pki p{dir / "pki"};
	CHECK(!p.exists());
	p.create();
	CHECK(p.exists());
	CHECK(fs::exists(p.root_private_key_file()));
	CHECK(fs::exists(p.root_public_key_file()));
	CHECK(fs::exists(p.ca_private_key_file()));
	CHECK(fs::exists(p.ca_certificate_file()));
#ifndef _WIN32
	auto owner_only = fs::perms::owner_read | fs::perms::owner_write;
	CHECK(fs::status(p.root_private_key_file()).permissions() == owner_only);
	CHECK(fs::status(p.ca_private_key_file()).permissions() == owner_only);
	CHECK(fs::status(p.root_public_key_file()).permissions() != owner_only);
#endif

	REQUIRE(crypto::has_root_public_key());
	CHECK(crypto::root_public_key().id() == p.root().id());
	CHECK(crypto::load_public_key_file(p.root_public_key_file().string()).id() == p.root().id());

	CHECK(p.ca_chain().is_valid());
	CHECK(p.ca_chain().root_key_id() == p.root().id());
	CHECK(p.ca_chain().subject().id() == p.ca().id());
	CHECK(p.ca_chain().subject_ca_level() == 1);
	CHECK(p.ca_chain().is_authentic(keys, certs));

	CHECK_THROWS(p.create());
}

TEST_CASE_METHOD(fixture, "keygen pki load restores the same material", "[keygen]") {
	pki first{dir / "pki"};
	first.create();
	crypto::clear_root_public_key();

	pki second{dir / "pki"};
	second.load();
	CHECK(second.root().id() == first.root().id());
	CHECK(second.ca().id() == first.ca().id());
	REQUIRE(crypto::has_root_public_key());
	CHECK(crypto::root_public_key().id() == first.root().id());

	// the loaded CA key still signs chains the root accepts
	auto key = crypto::generate_private_key(second.ca().suite());
	auto chain = second.certify(key);
	CHECK(chain.is_authentic(keys, certs));
	CHECK(chain.subject().id() == key.id());

	pki missing{dir / "none"};
	CHECK(!missing.exists());
	CHECK_THROWS(missing.load());
}

TEST_CASE_METHOD(fixture, "keygen pki load rejects a CA certificate from another root", "[keygen][security]") {
	pki p{dir / "pki"};
	p.create();
	pki other{dir / "other"};
	other.create();
	fs::copy_file(other.ca_certificate_file(), p.ca_certificate_file(), fs::copy_options::overwrite_existing);
	pki tampered{dir / "pki"};
	CHECK_THROWS(tampered.load());
}

TEST_CASE_METHOD(fixture, "keygen certify gives a chain the root accepts with the hostname restriction", "[keygen]") {
	pki p{dir / "pki"};
	p.create();
	auto key = crypto::generate_private_key(p.ca().suite());
	auto chain = p.certify(key, "host.example.org");

	CHECK(chain.root_key_id() == p.root().id());
	CHECK(chain.subject().id() == key.id());
	CHECK(chain.subject_ca_level() == 0);
	CHECK(chain.subject_restrictions().hostname() == "host.example.org");
	CHECK(chain.is_authentic(keys, certs));
	CHECK(chain.is_authentic(keys, certs, crypto::key_cert_restriction().hostname("host.example.org")));
	CHECK(chain.is_authentic(keys, certs, crypto::key_cert_restriction().hostname("sub.host.example.org")));
	CHECK(!chain.is_authentic(keys, certs, crypto::key_cert_restriction().hostname("other.example.org")));
	// the key's public half references the certificate the chain ends in
	CHECK(key.public_key().id() == chain.subject().id());

	auto unrestricted = crypto::generate_private_key(p.ca().suite());
	auto any_host = p.certify(unrestricted);
	CHECK(!any_host.subject_restrictions().has_hostname());
	CHECK(any_host.is_authentic(keys, certs, crypto::key_cert_restriction().hostname("anything.example.org")));

	// a chain from a different pki is not accepted once this root is the anchor again
	pki other{dir / "other"};
	other.create();
	auto other_key = crypto::generate_private_key(other.ca().suite());
	auto other_chain = other.certify(other_key);
	CHECK(other_chain.is_authentic(keys, certs));
	crypto::set_root_public_key(p.root().public_key());
	CHECK(!other_chain.is_authentic(keys, certs));
	CHECK(chain.is_authentic(keys, certs));
}

TEST_CASE_METHOD(fixture, "keygen install_identity stores the own key and refuses a second one", "[keygen]") {
	pki p{dir / "pki"};
	p.create();
	identity_stores server{file("srv/private_data.db"), file("srv/public_key.db")};
	auto key = install_identity(p, server, "srv.example.org");

	{
		crypto::private_data_database priv(database::sqlite::create_sqlite_connection(server.private_data_db));
		auto stored = priv.my_private_key();
		REQUIRE(stored);
		CHECK(stored->id() == key.id());
		auto chain = priv.my_certificate_chain();
		REQUIRE(chain);
		CHECK(chain->subject().id() == key.id());
		CHECK(chain->is_authentic(keys, certs, crypto::key_cert_restriction().hostname("srv.example.org")));
		crypto::public_key_database pub(database::sqlite::create_sqlite_connection(server.public_key_db));
		CHECK(pub.find(key.id()));
	}
#ifndef _WIN32
	CHECK(fs::status(server.private_data_db).permissions() == (fs::perms::owner_read | fs::perms::owner_write));
#endif
	CHECK_THROWS(install_identity(p, server));

	// a client keeps both stores in one file
	identity_stores client{file("client/client.db"), file("client/client.db")};
	auto client_key = install_identity(p, client);
	crypto::private_data_database priv(database::sqlite::create_sqlite_connection(client.private_data_db));
	REQUIRE(priv.my_private_key());
	CHECK(priv.my_private_key()->id() == client_key.id());
	REQUIRE(priv.my_certificate_chain());
	CHECK(priv.my_certificate_chain()->is_authentic(keys, certs));
	crypto::public_key_database pub(database::sqlite::create_sqlite_connection(client.public_key_db));
	CHECK(pub.find(client_key.id()));
}

}
