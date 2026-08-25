// SPDX-License-Identifier: MIT

#include "private_data_cache.hpp"

namespace securepath::crypto {

private_data_cache::private_data_cache(private_data_access_ptr backend) {
	add_backend(std::move(backend));
}

std::optional<private_key> private_data_cache::my_private_key() const {
	lock_guard l{mutex_};
	if(!my_key_) {
		for(auto it = backends_.begin(); it != backends_.end() && !(my_key_ = (*it)->my_private_key()); ++it) {}
	}
	return my_key_;
}

void private_data_cache::set_my_private_key(private_key const& key) {
	lock_guard l{mutex_};
	my_key_ = key;
	for(auto&& v : backends_) {
		v->set_my_private_key(key);
	}
}

std::optional<certificate_chain> private_data_cache::my_certificate_chain() const {
	lock_guard l{mutex_};
	if(!my_chain_) {
		for(auto it = backends_.begin(); it != backends_.end() && !(my_chain_ = (*it)->my_certificate_chain()); ++it) {}
	}
	return my_chain_;
}

void private_data_cache::set_my_certificate_chain(certificate_chain const& chain) {
	lock_guard l{mutex_};
	my_chain_ = chain;
	for(auto&& v : backends_) {
		v->set_my_certificate_chain(chain);
	}
}

void private_data_cache::insert(key_type const& key, octet_vector data) {
	lock_guard l{mutex_};
	metadata_[key] = data;
	for(auto&& v : backends_) {
		v->insert(key, data);
	}
}

std::optional<octet_vector> private_data_cache::find(key_type const& key) const {
	lock_guard l{mutex_};
	std::optional<octet_vector> ret;
	auto it = metadata_.find(key);
	if(it != metadata_.end()) {
		ret = it->second;
	}
	if(!ret) {
		for(auto bit = backends_.begin(); bit != backends_.end() && !(ret = (*bit)->find(key)); ++bit) {}
		if(ret) {
			metadata_[key] = *ret;
		}
	}
	return ret;
}

void private_data_cache::erase(key_type const& key) {
	lock_guard l{mutex_};
	metadata_.erase(key);
	for(auto&& v : backends_) {
		v->erase(key);
	}
}

void private_data_cache::add_backend(private_data_access_ptr access) {
	lock_guard l{mutex_};
	backends_.insert(std::move(access));
}

}
