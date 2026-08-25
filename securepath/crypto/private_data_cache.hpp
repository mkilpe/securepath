// SPDX-License-Identifier: MIT

#pragma once

#include "private_data_access.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <set>

namespace securepath::crypto {

/**
 * Cached storage for private data
 */
class private_data_cache : public private_data_access {
public:
	private_data_cache() = default;
	private_data_cache(private_data_access_ptr backend);

	using private_data_access::insert;
	using private_data_access::find;

	std::optional<private_key> my_private_key() const override;
	void set_my_private_key(private_key const&) override;
	std::optional<certificate_chain> my_certificate_chain() const override;
	void set_my_certificate_chain(certificate_chain const&) override;
	void insert(key_type const& key, octet_vector) override;
	std::optional<octet_vector> find(key_type const& key) const override;
	void erase(key_type const& key) override;

	void add_backend(private_data_access_ptr access);

private:
	using mutex_type = std::mutex;
	using lock_guard = std::lock_guard<mutex_type>;

private:
	mutable mutex_type mutex_;
	mutable std::optional<private_key> my_key_;
	mutable std::optional<certificate_chain> my_chain_;
	mutable std::map<key_type, octet_vector> metadata_;
	std::set<private_data_access_ptr> backends_;
};

}
