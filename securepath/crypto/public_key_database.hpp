// SPDX-License-Identifier: MIT

#pragma once

#include "public_key_access.hpp"

#include <securepath/database/connection.hpp>

#include <optional>

namespace securepath::crypto {

/// Public keys in a sqlite table (public_keys: id hex TEXT primary key, DER BLOB)
class public_key_database : public public_key_access {
public:
	public_key_database(database::connection_ptr c);

	void insert(public_key const&) override;
	void remove(public_key_id const&) override;
	std::optional<public_key> find(public_key_id const&) const override;

private:
	database::connection_ptr db_;
};

}
