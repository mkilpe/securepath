// SPDX-License-Identifier: MIT

#pragma once

#include "certificate_access.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace securepath::crypto {

/// In-memory certificate store that reads through to and writes through all attached backends
class certificate_cache : public certificate_access {
public:
	certificate_cache() = default;
	certificate_cache(certificate_access_ptr backend);

	/// throws error(errc::invalid_operation) when trying to replace a revoked certificate
	void insert(certificate const&) override;
	void remove(certificate_id const&) override;
	std::optional<certificate> find(certificate_id const&) const override;
	std::vector<certificate> search_identifier(std::string const& identifier) const override;

	void add_backend(certificate_access_ptr access);

private:
	using mutex_type = std::mutex;
	using lock_guard = std::lock_guard<mutex_type>;

private:
	mutable mutex_type mutex_;
	mutable std::map<certificate_id, certificate> certs_;
	std::set<certificate_access_ptr> backends_;
};

}
