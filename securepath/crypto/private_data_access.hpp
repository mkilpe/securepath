// SPDX-License-Identifier: MIT

#pragma once

#include "certificate_chain.hpp"
#include "error.hpp"
#include "private_key.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/types.hpp>

#include <memory>
#include <optional>
#include <string>

namespace securepath::crypto {

/**
 * Data access for private data, like private key.
 */
class private_data_access {
public:
	using key_type = std::string;

	private_data_access() = default;
	virtual ~private_data_access() = default;

	private_data_access(private_data_access const&) = delete;
	private_data_access& operator=(private_data_access const&) = delete;

	/// returns private key if default private key set
	virtual std::optional<private_key> my_private_key() const = 0;
	/// set the default private key, overwrites the existing default private key if set
	virtual void set_my_private_key(private_key const&) = 0;

	/// returns certificate chain for your own key if set
	virtual std::optional<certificate_chain> my_certificate_chain() const = 0;
	/// set certificate chain for my default key
	virtual void set_my_certificate_chain(certificate_chain const&) = 0;

	/// insert (or replace) octet vector raw data
	virtual void insert(key_type const& key, octet_vector) = 0;
	/// find data matching the key
	virtual std::optional<octet_vector> find(key_type const& key) const = 0;
	/// remove data associated with the key
	virtual void erase(key_type const& key) = 0;

	/// find data matching the key and return typed object
	/// \throws serialisation_error if type of the serialised object doesn't match
	template<typename Data>
	std::optional<Data> find(key_type const& key) const {
		std::optional<Data> ret;
		auto v = find(key);
		if(v) {
			ret = serialisation::asn_der_deserialise<Data>(*v);
		}
		return ret;
	}

	/// insert (or replace) typed data which will be serialised
	template<typename Data>
	void insert(key_type const& key, Data const& data) {
		insert(key, serialisation::asn_der_serialise(data));
	}
};

using private_data_access_ptr = std::shared_ptr<private_data_access>;

/// helper function that throws if own private key is not set
inline private_key my_private_key(private_data_access const& access) {
	auto key = access.my_private_key();
	if(!key) {
		LOG_WARN("own private key not set");
		throw error(make_error_code(errc::no_such_key));
	}
	return *key;
}

}
