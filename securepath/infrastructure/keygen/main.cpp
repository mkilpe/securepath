// SPDX-License-Identifier: MIT

// sp_keygen: the key material of a deployment (see doc/keygen.md).
//
// Every process authenticates with a certificate chain that ends in one root public key: the
// daemons present theirs in the handshake and the clients present theirs where a server requires
// it. The tool keeps a pki directory (root key, CA key and its certificate) and certifies server
// and client keys with it:
//
//   sp_keygen --pki DIR --init                    create the root and CA into DIR
//   sp_keygen --pki DIR --server DIR2 [--host H]  server key + chain into DIR2/private_data.db
//   sp_keygen --pki DIR --client FILE             client key + chain into the sqlite FILE
//                                                 (a client keeping all its stores in one file)
//
// The processes load DIR/root.pub with their --root option. The printed key id is what peers
// use to refer to the process.

#include "pki.hpp"

#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/command_parser.hpp>
#include <securepath/version.hpp>

#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace securepath::keygen {
namespace {

struct parameters : command_parser {
	bool help{};
	std::string pki_dir;
	bool init{};
	std::string server;
	std::string client;
	std::string host;

	parameters() {
		add(help, "help", "h", "show help");
		add(pki_dir, "pki", "", "directory of the root and CA material");
		add(init, "init", "", "create a new root and CA into the pki directory");
		add(server, "server", "", "directory to write a certified server key into (private_data.db, public_key.db)");
		add(client, "client", "", "sqlite file to write a certified client key into");
		add(host, "host", "", "hostname restriction of the server certificate (none by default)");
	}
};

void make_server(pki const& p, std::string const& dir, std::string const& host) {
	std::filesystem::path d{dir};
	identity_stores stores{(d / "private_data.db").string(), (d / "public_key.db").string()};
	auto key = install_identity(p, stores, host);
	std::cout << "server key " << key.id().in_hex() << " written to " << dir << "\n";
}

void make_client(pki const& p, std::string const& file) {
	auto key = install_identity(p, identity_stores{file, file});
	std::cout << "client key " << key.id().in_hex() << " written to " << file << "\n";
}

void print_keys(pki const& p) {
	std::cout << "root key " << p.root().id().in_hex() << ", CA key " << p.ca().id().in_hex() << "\n";
}

int run(parameters const& p) {
	if(p.pki_dir.empty()) {
		throw std::runtime_error("--pki is required");
	}
	pki material{p.pki_dir};
	if(p.init) {
		material.create();
		std::cout << "created pki in " << p.pki_dir << " (root public key for --root: "
			<< material.root_public_key_file().string() << ")\n";
		print_keys(material);
	} else {
		material.load();
	}
	if(!p.server.empty()) {
		make_server(material, p.server, p.host);
	}
	if(!p.client.empty()) {
		make_client(material, p.client);
	}
	if(!p.init && p.server.empty() && p.client.empty()) {
		print_keys(material);
	}
	return 0;
}

}
}

int main(int argc, char* args[]) {
	int ret = -1;
	try {
		using namespace securepath;
		log::backend::add_backend<log::backend::file_output>("file", "sp_keygen.log");
		keygen::parameters p;
		p.parse(argc, args);
		if(p.help) {
			std::cout << "securepath key generator (library version " << library_version() << ")\n";
			p.print_help(std::cout);
			ret = 0;
		} else {
			ret = keygen::run(p);
		}
	} catch(std::exception const& ex) {
		LOG_WARN("Error: {}", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
	}
	return ret;
}
