// SPDX-License-Identifier: MIT

#pragma once

#include "key_value_access.hpp"
#include <securepath/database/connection.hpp>

namespace securepath {

class key_value_database : public key_value_access {
public:
	key_value_database(database::connection_ptr, std::string table, std::uint64_t selector = 0);

	/// insert (or replace) octet vector raw data
	void insert(key_type const& key, octet_vector const&) override;

	/// find data matching the key
	std::optional<octet_vector> find(key_type const& key) const override;

	/// remove data associated with the key
	void erase(key_type const& key) override;

	/// remove all data
	void clear() override;

	using key_value_access::insert;
	using key_value_access::find;

private:
	database::connection_ptr db_;
	std::string const table_;
	std::uint64_t const selector_;
};

}
