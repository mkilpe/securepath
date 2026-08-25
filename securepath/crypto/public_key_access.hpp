// SPDX-License-Identifier: MIT

#pragma once

#include "public_key.hpp"
#include "public_key_id.hpp"
#include "root_public_key.hpp"

#include <memory>
#include <optional>

namespace securepath::crypto {

class public_key_access {
public:
	public_key_access() = default;
	virtual ~public_key_access() = default;

	public_key_access(public_key_access const&) = delete;
	public_key_access& operator=(public_key_access const&) = delete;

	virtual void insert(public_key const&) = 0;
	virtual void remove(public_key_id const&) = 0;
	virtual std::optional<public_key> find(public_key_id const&) const = 0;

	/// request root key, this default implementation only returns root_public_key() if the id not set or matches
	/// (and nothing when no root key has been set)
	virtual std::optional<public_key> find_root_key(std::optional<public_key_id> = std::nullopt) const;
};

using public_key_access_ptr = std::shared_ptr<public_key_access>;

}
