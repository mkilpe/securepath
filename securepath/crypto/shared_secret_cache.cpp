// SPDX-License-Identifier: MIT

#include "shared_secret_cache.hpp"

namespace securepath::crypto {

shared_secret_cache::shared_secret_cache(shared_secret_access_ptr backend) {
	backends_.insert(std::move(backend));
}

void shared_secret_cache::add_backend(shared_secret_access_ptr backend) {
	lock_guard l{mutex_};
	backends_.insert(std::move(backend));
}

void shared_secret_cache::insert(octet_span const& key, octet_span const& data) {
	lock_guard l{mutex_};
	if(key.empty()) {
		throw invalid_secret_key_size();
	}
	secrets_[octet_vector(key.begin(), key.end())] = octet_vector(data.begin(), data.end());
	for(auto&& b : backends_) {
		b->insert(key, data);
	}
}

void shared_secret_cache::remove(octet_span const& key) {
	lock_guard l{mutex_};
	secrets_.erase(octet_vector(key.begin(), key.end()));
	for(auto&& b : backends_) {
		b->remove(key);
	}
}

std::optional<octet_vector> shared_secret_cache::find(octet_span const& key) const {
	lock_guard l{mutex_};
	std::optional<octet_vector> res;
	octet_vector key_o(key.begin(), key.end());
	auto it = secrets_.find(key_o);
	if(it != secrets_.end()) {
		res = it->second;
	} else {
		for(auto i = backends_.begin(); i != backends_.end() && !(res = (*i)->find(key)); ++i) {}
		if(res) {
			secrets_[key_o] = *res;
		}
	}
	return res;
}

}
