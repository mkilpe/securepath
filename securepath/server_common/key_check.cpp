// SPDX-License-Identifier: MIT

#include "key_check.hpp"

#include <securepath/crypto/certificate_chain.hpp>
#include <securepath/crypto/private_data_access.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>

namespace securepath::server_common {

void check_server_key(network::context const& context) {
	LOG_INFO("checking private key and certificate chain...");
	auto my_key = context.private_data().my_private_key();
	if(!my_key) {
		LOG_WARN("no private key found for the server");
		throw make_error(securepath::errc::invalid_state, "no private key found for the server");
	}

	// the keys and certs do not need to be in the general accesses, the own certificate chain is used
	auto my_chain = context.private_data().my_certificate_chain();
	if(!my_chain) {
		LOG_WARN("no certificate chain set for the server");
		throw make_error(securepath::errc::invalid_state, "no certificate chain set for the server");
	}
	LOG_INFO("own certificate chain set to {}", *my_chain);
}

}
