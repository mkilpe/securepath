// SPDX-License-Identifier: MIT

#include "encrypted_net_base.hpp"

#include <securepath/crypto/certificate_database.hpp>
#include <securepath/crypto/private_data_database.hpp>
#include <securepath/crypto/public_key_database.hpp>
#include <securepath/crypto/shared_secret_database.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/log/log.hpp>

namespace securepath::network {

namespace {

template<typename Access>
std::shared_ptr<Access> non_owning(Access& access) {
	return std::shared_ptr<Access>(&access, [](Access*) {});
}

}

encrypted_net_base::encrypted_net_base(net_type_tag, encrypted_net_base_params params)
: params_(std::move(params))
{
}

encrypted_net_base::encrypted_net_base(network::context& context)
: context_(&context)
{
}

bool encrypted_net_base::init() {
	if(context_) {
		keys_.add_backend(non_owning(context_->public_keys()));
		certs_.add_backend(non_owning(context_->certificates()));
		shared_secrets_.add_backend(non_owning(context_->shared_secrets()));
		private_data_.add_backend(non_owning(context_->private_data()));
	} else {
		keys_.add_backend(std::make_shared<crypto::public_key_database>(
			database::sqlite::create_sqlite_connection(params_.public_key_db)));
		certs_.add_backend(std::make_shared<crypto::certificate_database>(
			database::sqlite::create_sqlite_connection(params_.cert_db)));
		shared_secrets_.add_backend(std::make_shared<crypto::shared_secret_database>(
			database::sqlite::create_sqlite_connection(params_.shared_secret_db)));
		private_data_.add_backend(std::make_shared<crypto::private_data_database>(
			database::sqlite::create_sqlite_connection(params_.private_data_db)));
	}
	return true;
}

crypto::public_key_access& encrypted_net_base::keys() {
	return keys_;
}

crypto::certificate_access& encrypted_net_base::certs() {
	return certs_;
}

crypto::shared_secret_access& encrypted_net_base::shared_secrets() {
	return shared_secrets_;
}

crypto::private_data_access& encrypted_net_base::private_data() {
	return private_data_;
}

network::context encrypted_net_base::construct_context() {
	return network::context(io_context(), keys(), certs(), shared_secrets(), private_data());
}

}
