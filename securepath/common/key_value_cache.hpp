// SPDX-License-Identifier: MIT

#pragma once

#include "key_value_access.hpp"

#include <map>
#include <mutex>
#include <set>

namespace securepath {
/// Common metadata access interface
class key_value_cache : public key_value_access {
public:
	key_value_cache() = default;
	key_value_cache(key_value_access_ptr backend);

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

	/// add access to this cache
	void add_backend(key_value_access_ptr access);

private:
	using mutex_type = std::mutex;
	using lock_guard = std::lock_guard<mutex_type>;

	mutable mutex_type mutex_;
	mutable std::map<std::string, octet_vector> data_;
	std::set<key_value_access_ptr> backends_;
};

}
