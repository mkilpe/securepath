// SPDX-License-Identifier: MIT

#include "pt_test_context.hpp"

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_access.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

#include <cassert>

namespace securepath::packet_transport::test {

pt_test_context::pt_test_context(int threads) {
	for(int i = 0; i != threads; ++i) {
		threads_.emplace_back([&]{ io_.run(); });
	}

	auto server_key = crypto::generate_private_key();
	server_.private_data.set_my_private_key(server_key);
	server_.private_data.set_my_certificate_chain(pki_context_.chain_for_server_key(server_key, {}));
	network::enable_server_pk_handshake(server_.context);
}

pt_test_context::~pt_test_context() {
	io_guard_.reset();
	for(auto& t : threads_) {
		t.join();
	}
}

void pt_test_context::add_client(int amount) {
	for(int i = 0; i != amount; ++i) {
		clients_.push_back(std::make_unique<instance>(io_, pki_context_.root.public_key()));
		auto priv_key = crypto::generate_private_key();
		clients_.back()->private_data.set_my_private_key(priv_key);
		// the server authenticates clients: every client needs a certified key
		clients_.back()->private_data.set_my_certificate_chain(pki_context_.chain_for_server_key(priv_key, {}));
		clients_.back()->keys.insert(priv_key.public_key());
		network::enable_client_pk_handshake(clients_.back()->context);
	}
}

pt_test_context::instance& pt_test_context::client(int n) {
	assert(n < static_cast<int>(clients_.size()));
	return *clients_[n];
}

pt_test_context::instance const& pt_test_context::client(int n) const {
	assert(n < static_cast<int>(clients_.size()));
	return *clients_[n];
}

network::context& pt_test_context::client_context(int n) {
	return client(n).context;
}

network::context& pt_test_context::server_context() {
	return server_.context;
}

void pt_test_context::add_client_keys_for_server() {
	for(auto&& v : clients_) {
		server_.keys.insert(my_private_key(v->private_data).public_key());
	}
}

void pt_test_context::share_client_keys() {
	for(auto&& v1 : clients_) {
		for(auto&& v2 : clients_) {
			v1->keys.insert(my_private_key(v2->private_data).public_key());
		}
	}
}

crypto::public_key_id pt_test_context::key_id(int n) const {
	return my_private_key(client(n).private_data).id();
}

}
