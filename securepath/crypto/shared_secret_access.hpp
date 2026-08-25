// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <memory>
#include <optional>

namespace securepath::crypto {

struct invalid_secret_key_size : crypto_error { using crypto_error::crypto_error; };

/// Key -> secret store (pre-shared secrets for the shared secret handshake etc.)
class shared_secret_access {
public:
	shared_secret_access() = default;
	virtual ~shared_secret_access() = default;

	shared_secret_access(shared_secret_access const&) = delete;
	shared_secret_access& operator=(shared_secret_access const&) = delete;

	/// throws invalid_secret_key_size() on empty key
	virtual void insert(octet_span const& key, octet_span const& data) = 0;
	virtual void remove(octet_span const& key) = 0;
	virtual std::optional<octet_vector> find(octet_span const& key) const = 0;
};

using shared_secret_access_ptr = std::shared_ptr<shared_secret_access>;

}
