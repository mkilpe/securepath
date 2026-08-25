// SPDX-License-Identifier: MIT

#pragma once

#include "certificate.hpp"
#include "certificate_id.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securepath::crypto {

class certificate_access {
public:
	certificate_access() = default;
	virtual ~certificate_access() = default;

	certificate_access(certificate_access const&) = delete;
	certificate_access& operator=(certificate_access const&) = delete;

	virtual void insert(certificate const&) = 0;
	virtual void remove(certificate_id const&) = 0;
	virtual std::optional<certificate> find(certificate_id const&) const = 0;
	virtual std::vector<certificate> search_identifier(std::string const& identifier) const = 0;
};

using certificate_access_ptr = std::shared_ptr<certificate_access>;

}
