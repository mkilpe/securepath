// SPDX-License-Identifier: MIT

#pragma once

#include "public_key_access.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <set>

namespace securepath::crypto {

/// In-memory public key store that reads through to and writes through all attached backends
class public_key_cache : public public_key_access {
public:
	public_key_cache() = default;
	public_key_cache(public_key_access_ptr backend);

	void insert(public_key const&) override;
	void remove(public_key_id const&) override;
	std::optional<public_key> find(public_key_id const&) const override;

	void add_backend(public_key_access_ptr access);

private:
	using mutex_type = std::mutex;
	using lock_guard = std::lock_guard<mutex_type>;

private:
	mutable mutex_type mutex_;
	mutable std::map<public_key_id, public_key> keys_;
	std::set<public_key_access_ptr> backends_;
};

}
