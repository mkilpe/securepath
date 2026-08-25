// SPDX-License-Identifier: MIT

#pragma once

#include "shared_secret_access.hpp"

#include <securepath/database/connection.hpp>

#include <optional>

namespace securepath::crypto {

/// Shared secrets in a sqlite table (secrets: key hex TEXT primary key, data BLOB)
class shared_secret_database : public shared_secret_access {
public:
	shared_secret_database(database::connection_ptr c);

	void insert(octet_span const& key, octet_span const& data) override;
	void remove(octet_span const& key) override;
	std::optional<octet_vector> find(octet_span const& key) const override;

private:
	database::connection_ptr db_;
};

}
