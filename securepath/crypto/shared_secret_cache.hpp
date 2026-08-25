// SPDX-License-Identifier: MIT

#pragma once

#include "shared_secret_access.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <set>

namespace securepath::crypto {

/// In-memory shared secret store that reads through to and writes through all attached backends
class shared_secret_cache : public shared_secret_access {
public:
	shared_secret_cache() = default;
	shared_secret_cache(shared_secret_access_ptr backend);

	void add_backend(shared_secret_access_ptr backend);

	void insert(octet_span const& key, octet_span const& data) override;
	void remove(octet_span const& key) override;
	std::optional<octet_vector> find(octet_span const& key) const override;

private:
	using mutex_type = std::mutex;
	using lock_guard = std::lock_guard<mutex_type>;

private:
	mutable mutex_type mutex_;
	mutable std::map<octet_vector, octet_vector> secrets_;
	std::set<shared_secret_access_ptr> backends_;
};

}
