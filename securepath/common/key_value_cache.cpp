// SPDX-License-Identifier: MIT

#include "key_value_cache.hpp"

namespace securepath {

key_value_cache::key_value_cache(key_value_access_ptr backend) {
	add_backend(backend);
}

void key_value_cache::insert(key_type const& key, octet_vector const& data) {
	lock_guard l{mutex_};
	data_[key] = data;
	for(auto&& v : backends_) {
		v->insert(key, data);
	}
}

std::optional<octet_vector> key_value_cache::find(key_type const& key) const {
	lock_guard l{mutex_};
	std::optional<octet_vector> ret;
	auto it = data_.find(key);
	if(it != data_.end()) {
		ret = it->second;
	}
	if(!ret) {
		for(auto it = backends_.begin(); it != backends_.end() && !(ret = (*it)->find(key)); ++it) {}
		if(ret) {
			data_[key] = *ret;
		}
	}
	return ret;
}

void key_value_cache::erase(key_type const& key) {
	lock_guard l{mutex_};
	data_.erase(key);
	for(auto&& v : backends_) {
		v->erase(key);
	}
}

void key_value_cache::clear() {
	lock_guard l{mutex_};
	data_.clear();
	for(auto&& v : backends_) {
		v->clear();
	}
}

void key_value_cache::add_backend(key_value_access_ptr access) {
	lock_guard l{mutex_};
	backends_.insert(access);
}

}
