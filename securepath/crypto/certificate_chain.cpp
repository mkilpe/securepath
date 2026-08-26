// SPDX-License-Identifier: MIT

#include "certificate_chain.hpp"

#include "certificate_access.hpp"
#include "error.hpp"
#include "public_key_access.hpp"

#include <securepath/log/log.hpp>

#include <algorithm>
#include <limits>
#include <ostream>

namespace securepath::crypto {

certificate_chain::certificate_chain(public_key_id root, std::vector<key_cert_pair> chain)
: root_key_id_(std::move(root))
, chain_(std::move(chain))
{
}

bool certificate_chain::is_valid() const {
	return begin() != end() && root_key_id_.is_valid();
}

public_key certificate_chain::subject() const {
	if(!is_valid()) {
		throw error(make_error_code(errc::invalid_certificate_chain));
	}
	return chain_.back().subject;
}

namespace {

struct check_data {
	int ca_level{};
	key_cert_restriction restriction;
};

error check_link_certificate(public_key const& key, certificate const& cert, public_key const& previous_key) {
	if(!cert.is_authentic(previous_key)) {
		LOG_WARN("failed to verify certificate ({})", cert.id());
		return error(errc::invalid_certificate);
	}
	if(!key.verify_me()) {
		LOG_WARN("failed to verify subject public key ({})", key.id());
		return error(errc::invalid_public_key);
	}
	if(cert.type() != key_certificate_data::id) {
		LOG_WARN("invalid certificate type for certificate chain ({})", cert.type());
		return error(errc::invalid_certificate);
	}
	if(previous_key.id() != cert.issuer()) {
		LOG_WARN("existing chain subject does not match with certificate issuer (subject: {} - issuer: {})", previous_key.id(), cert.issuer());
		return error(errc::invalid_data);
	}
	return error();
}

error check_link_data(public_key const& key, certificate const& cert, key_certificate_data const& key_cert, check_data& data) {
	if(key_cert.subject() != key.id()) {
		LOG_WARN("key certificate subject does not match with public key (key: {} - cert: {})", key_cert.subject(), key.id());
		return error(errc::invalid_data);
	}
	if(!key.references_certificate(cert.id())) {
		LOG_WARN("subject key does not reference certificate (key: {} - cert: {})", key_cert.subject(), cert.id());
		return error(errc::invalid_data);
	}
	if(data.ca_level <= key_cert.ca_level()) {
		LOG_WARN("bad certificate ca level ({} <= {})", data.ca_level, key_cert.ca_level());
		return error(errc::invalid_certificate_chain_ca_level);
	}
	data.ca_level = key_cert.ca_level();
	if(!key_cert.restrictions().is_subset_of(data.restriction)) {
		LOG_WARN("bad key certificate restriction ('{}' not subset of '{}')", key_cert.restrictions(), data.restriction);
		return error(errc::invalid_data);
	}
	data.restriction = key_cert.restrictions();
	return error();
}

error check_link(public_key const& key, certificate const& cert, public_key const& previous_key, check_data& data) {
	error err = check_link_certificate(key, cert, previous_key);
	if(!err) {
		err = check_link_data(key, cert, cert.extract<key_certificate_data>(), data);
	}
	return err;
}

struct chain_verify {
	bool check_chain_element(key_cert_pair const& elem) {
		check_data data{previous_ca_level, previous_restriction};
		error err = check_link(elem.subject, elem.cert, previous, data);
		if(err) {
			LOG_WARN("check_chain_element failed: {}", err);
			return false;
		}
		if(is_revoked_in_store(elem.cert)) {
			return false;
		}
		previous = elem.subject;
		previous_ca_level = data.ca_level;
		previous_restriction = data.restriction;
		return true;
	}

	// Consult the verifier's own certificate store, not only the revocation the peer chose
	// to present. A revoked certificate whose stapled revocation was omitted is caught here
	// (doc/threat_model.md F1). 'previous' is the issuer key for elem.cert at this point.
	bool is_revoked_in_store(certificate const& cert) const {
		if(!certs) {
			return false;
		}
		auto stored = certs->find(cert.id());
		if(stored && stored->is_revoked(previous)) {
			LOG_WARN("certificate revoked per trusted store: {}", cert.id());
			return true;
		}
		return false;
	}

	public_key previous;
	int previous_ca_level{std::numeric_limits<int>::max()};
	key_cert_restriction previous_restriction;
	certificate_access const* certs{};
};

}

bool certificate_chain::is_authentic(public_key_access const& keys, certificate_access const& certs) const {
	if(chain_.size() > max_chain_length) {
		LOG_WARN("certificate chain too long ({} links, max {})", chain_.size(), max_chain_length);
		return false;
	}
	bool res = is_valid();
	if(res) {
		std::optional<public_key> root = keys.find_root_key(root_key_id_);
		res = root.has_value();
		if(res) {
			chain_verify ver{*root};
			ver.certs = &certs;
			for(auto it = begin(); res && it != end(); ++it) {
				res = ver.check_chain_element(*it);
			}
		} else {
			LOG_WARN("no such root key: {}", root_key_id_);
		}
	} else {
		LOG_WARN("invalid chain");
	}
	return res;
}

bool certificate_chain::is_authentic(public_key_access const& keys, certificate_access const& certs, key_cert_restriction const& rest) const {
	return is_authentic(keys, certs) && rest.is_subset_of(subject_restrictions());
}

std::uint16_t certificate_chain::subject_ca_level() const {
	if(!is_valid()) {
		throw error(make_error_code(errc::invalid_certificate_chain));
	}
	auto key_cert = chain_.back().cert.extract<key_certificate_data>();
	return key_cert.ca_level();
}

key_cert_restriction certificate_chain::subject_restrictions() const {
	if(!is_valid()) {
		throw error(make_error_code(errc::invalid_certificate_chain));
	}
	auto key_cert = chain_.back().cert.extract<key_certificate_data>();
	return key_cert.restrictions();
}

void certificate_chain::add_link(public_key key, certificate cert) {
	if(chain_.empty()) {
		LOG_WARN("Using overload that can't handle empty chain, root key missing");
		throw error(errc::no_such_root_key);
	}
	check_data data{subject_ca_level(), subject_restrictions()};
	error err = check_link(key, cert, subject(), data);
	if(err) {
		LOG_WARN("failed to add link, check failed: {}", err);
		throw err;
	}
	chain_.push_back(key_cert_pair{std::move(key), std::move(cert)});
}

void certificate_chain::add_link(public_key_access const& keys, public_key key, certificate cert) {
	public_key previous_key;
	check_data data{std::numeric_limits<int>::max()};
	//if the chain is empty, we check for root key, otherwise for the subject key
	if(chain_.empty()) {
		auto root = keys.find_root_key(cert.issuer());
		if(!root) {
			LOG_WARN("invalid root key specified: {}", cert.issuer());
			throw error(errc::no_such_root_key);
		}
		previous_key = *root;
	} else {
		previous_key = subject();
		data.ca_level = subject_ca_level();
		data.restriction = subject_restrictions();
	}
	error err = check_link(key, cert, previous_key, data);
	if(err) {
		LOG_WARN("failed to add link, check failed: {}", err);
		throw err;
	}
	if(chain_.empty()) {
		root_key_id_ = previous_key.id();
	}
	chain_.push_back(key_cert_pair{std::move(key), std::move(cert)});
}

std::string to_string(certificate_chain const& chain) {
	std::string out = "{root_key_id=" + chain.root_key_id().in_hex() + ", ";
	bool first = true;
	for(auto&& v: chain) {
		if(!first) {
			out += ", ";
		}
		first = false;
		out += "[" + v.subject.id().in_hex() + ", " + v.cert.id().in_hex() + "]";
	}
	return out + "}";
}

std::ostream& operator<<(std::ostream& out, certificate_chain const& chain) {
	return out << to_string(chain);
}

namespace {

struct chain_builder {
	public_key_access const& keys;
	certificate_access const& certs;
	std::optional<certificate_chain> chain;

	void try_complete(certificate const& cert, std::vector<key_cert_pair> list) {
		LOG_TRACE("found a root key for chain, constructing chain (root={}, {} elements)", cert.issuer(), list.size());
		std::reverse(list.begin(), list.end());
		auto cc = certificate_chain{cert.issuer(), std::move(list)};
		if(cc.is_authentic(keys, certs)) {
			chain = cc;
		}
	}

	void follow_issuer(certificate const& cert, std::uint16_t ca_level, std::vector<key_cert_pair> list) {
		if(keys.find_root_key(cert.issuer())) {
			try_complete(cert, std::move(list));
		} else {
			auto key = keys.find(cert.issuer());
			if(key) {
				build_list(*key, ca_level, std::move(list));
			} else {
				LOG_WARN("no public key for kid {}", cert.issuer());
			}
		}
	}

	void consider(public_key const& subject, certificate const& cert, std::optional<std::uint16_t> last_ca_level, std::vector<key_cert_pair> const& list) {
		if(cert.type() != key_certificate_data::id) {
			LOG_TRACE("ignoring certificate with wrong type ({})", cert.id());
		} else {
			auto ca_level = cert.extract<key_certificate_data>().ca_level();
			if(!last_ca_level || *last_ca_level < ca_level) {
				auto copy = list;
				copy.push_back(key_cert_pair{subject, cert});
				follow_issuer(cert, ca_level, std::move(copy));
			} else {
				LOG_TRACE("ignoring certificate because of ca level ({})", cert.id());
			}
		}
	}

	void build_list(public_key const& subject, std::optional<std::uint16_t> last_ca_level, std::vector<key_cert_pair> list) {
		auto cert_ids = subject.get_cert_ids();
		for(auto it = cert_ids.begin(); !chain && it != cert_ids.end(); ++it) {
			auto cert = certs.find(*it);
			if(cert) {
				consider(subject, *cert, last_ca_level, list);
			} else {
				LOG_INFO("no certificate for cid {}", *it);
			}
		}
	}
};

}

std::optional<certificate_chain> create_certificate_chain(public_key const& subject, public_key_access const& keys, certificate_access const& certs) {
	chain_builder builder{keys, certs};
	builder.build_list(subject, std::nullopt, {});
	if(builder.chain) {
		LOG_TRACE("chain = {}", *builder.chain);
	}
	return builder.chain;
}

}
