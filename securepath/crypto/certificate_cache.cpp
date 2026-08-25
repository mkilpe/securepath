// SPDX-License-Identifier: MIT

#include "certificate_cache.hpp"

#include "error.hpp"

#include <securepath/log/log.hpp>

namespace securepath::crypto {

certificate_cache::certificate_cache(certificate_access_ptr backend) {
	backends_.insert(std::move(backend));
}

void certificate_cache::insert(certificate const& cert) {
	lock_guard l{mutex_};
	auto it = certs_.find(cert.id());
	if(it != certs_.end() && it->second.revocation()) {
		LOG_WARN("trying to replace revoked certificate ({})", cert.id());
		throw error(errc::invalid_operation);
	}
	certs_[cert.id()] = cert;
	for(auto&& b : backends_) {
		b->insert(cert);
	}
}

void certificate_cache::remove(certificate_id const& id) {
	lock_guard l{mutex_};
	certs_.erase(id);
	for(auto&& b : backends_) {
		b->remove(id);
	}
}

std::optional<certificate> certificate_cache::find(certificate_id const& cid) const {
	lock_guard l{mutex_};
	std::optional<certificate> ret;
	auto it = certs_.find(cid);
	if(it != certs_.end()) {
		ret = it->second;
	} else {
		for(auto i = backends_.begin(); i != backends_.end() && !(ret = (*i)->find(cid)); ++i) {}
		if(ret) {
			certs_[ret->id()] = *ret;
		}
	}
	return ret;
}

std::vector<certificate> certificate_cache::search_identifier(std::string const& identifier) const {
	lock_guard l{mutex_};
	std::vector<certificate> res;
	std::set<certificate_id> saved;
	for(auto&& b : backends_) {
		for(certificate const& cert : b->search_identifier(identifier)) {
			if(saved.insert(cert.id()).second) {
				res.push_back(cert);
			}
		}
	}
	return res;
}

void certificate_cache::add_backend(certificate_access_ptr access) {
	lock_guard l{mutex_};
	backends_.insert(std::move(access));
}

}
