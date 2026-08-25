// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/crypto/public_key_cache.hpp>

#include <optional>

namespace securepath::crypto::test {

/*
 * Public key cache for testing which specifies its own root key instead of the process-wide one
 */
struct public_key_test_cache : public_key_cache {
	explicit public_key_test_cache(public_key const& key)
	: root_key_(key)
	{
	}

	std::optional<public_key> find_root_key(std::optional<public_key_id> id = std::nullopt) const override {
		std::optional<public_key> ret;
		if(!id || *id == root_key_.id()) {
			ret = root_key_;
		}
		return ret;
	}

private:
	public_key root_key_;
};

}
