// SPDX-License-Identifier: MIT

#pragma once

#include "net_base.hpp"
#include "encryption/context.hpp"

#include <securepath/crypto/certificate_cache.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/shared_secret_cache.hpp>

#include <optional>
#include <string>

namespace securepath::network {

struct encrypted_net_base_params {
	std::string public_key_db{"public_key.db"};
	std::string cert_db{"certificates.db"};
	std::string private_data_db{"private_data.db"};
	std::string shared_secret_db{"shared_secret.db"};
};

enum class net_type_tag {
	client,
	server
};

net_type_tag constexpr client_tag{net_type_tag::client};
net_type_tag constexpr server_tag{net_type_tag::server};

/// Holds the crypto data accesses (backed by sqlite databases or an existing context) for encrypted
/// connections and can construct a network::context from them.
class encrypted_net_base : public net_base {
public:
	explicit encrypted_net_base(net_type_tag, encrypted_net_base_params params = {});
	explicit encrypted_net_base(network::context& context);

	crypto::public_key_access& keys();
	crypto::certificate_access& certs();
	crypto::shared_secret_access& shared_secrets();
	crypto::private_data_access& private_data();
	network::context construct_context();

protected:
	virtual bool init() override;

protected:
	encrypted_net_base_params params_;
	crypto::public_key_cache keys_;
	crypto::certificate_cache certs_;
	crypto::shared_secret_cache shared_secrets_;
	crypto::private_data_cache private_data_;
	network::context* context_{};
};

}
