// SPDX-License-Identifier: MIT

#pragma once

#include "private_data_access.hpp"

#include <securepath/database/connection.hpp>

#include <optional>

namespace securepath::crypto {

/**
 * Database storage for private data
 * Metadata keys starting with double underscores (__) are reserved for the implementation
 */
class private_data_database : public private_data_access {
public:
	private_data_database(database::connection_ptr);

	using private_data_access::insert;
	using private_data_access::find;

	std::optional<private_key> my_private_key() const override;
	void set_my_private_key(private_key const&) override;
	std::optional<certificate_chain> my_certificate_chain() const override;
	void set_my_certificate_chain(certificate_chain const&) override;
	void insert(key_type const& key, octet_vector) override;
	std::optional<octet_vector> find(key_type const& key) const override;
	void erase(key_type const& key) override;

private:
	database::connection_ptr db_;
};

}
