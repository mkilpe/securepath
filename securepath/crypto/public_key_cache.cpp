// SPDX-License-Identifier: MIT

#include "public_key_cache.hpp"

namespace securepath::crypto {

public_key_cache::public_key_cache(public_key_access_ptr backend) {
	add_backend(std::move(backend));
}

void public_key_cache::insert(public_key const& key) {
	lock_guard l{mutex_};
	keys_[key.id()] = key;
	for(auto&& v : backends_) {
		v->insert(key);
	}
}

std::optional<public_key> public_key_cache::find(public_key_id const& id) const {
	lock_guard l{mutex_};
	std::optional<public_key> ret;
	auto it = keys_.find(id);
	if(it != keys_.end()) {
		ret = it->second;
	} else {
		for(auto bit = backends_.begin(); bit != backends_.end() && !(ret = (*bit)->find(id)); ++bit) {}
		if(ret) {
			keys_[ret->id()] = *ret;
		}
	}
	return ret;
}

void public_key_cache::remove(public_key_id const& id) {
	lock_guard l{mutex_};
	keys_.erase(id);
	for(auto&& v : backends_) {
		v->remove(id);
	}
}

void public_key_cache::add_backend(public_key_access_ptr access) {
	lock_guard l{mutex_};
	backends_.insert(std::move(access));
}

}
