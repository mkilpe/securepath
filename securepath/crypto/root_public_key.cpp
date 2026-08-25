// SPDX-License-Identifier: MIT

#include "root_public_key.hpp"

#include "error.hpp"

#include <securepath/log/log.hpp>

#include <mutex>
#include <optional>

namespace securepath::crypto {

namespace {

struct root_key_store {
	std::mutex mutex;
	std::optional<public_key> key;
};

root_key_store& store() {
	static root_key_store s;
	return s;
}

}

void set_root_public_key(public_key const& key) {
	if(!key.is_valid()) {
		LOG_WARN("refusing to set an invalid root public key");
		throw error(make_error_code(errc::invalid_public_key), "root public key is not valid");
	}
	std::lock_guard l{store().mutex};
	store().key = key;
}

bool has_root_public_key() {
	std::lock_guard l{store().mutex};
	return store().key.has_value();
}

void clear_root_public_key() {
	std::lock_guard l{store().mutex};
	store().key.reset();
}

public_key root_public_key() {
	std::lock_guard l{store().mutex};
	if(!store().key) {
		throw error(make_error_code(errc::no_such_root_key), "root public key has not been set");
	}
	return *store().key;
}

}
