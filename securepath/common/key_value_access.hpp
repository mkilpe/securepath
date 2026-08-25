// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/octet_vector.hpp>
#include <securepath/serialisation/util.hpp>

#include <memory>
#include <optional>
#include <string>

namespace securepath {

/// Common metadata access interface
class key_value_access {
public:
	using key_type = std::string;

	virtual ~key_value_access() = default;

	/// insert (or replace) typed data which will be serialised
	template<typename Data>
	void insert(key_type const& key, Data const& data) {
		insert(key, serialisation::asn_der_serialise(data));
	}

	/// insert (or replace) octet vector raw data
	virtual void insert(key_type const& key, octet_vector const&) = 0;

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

	/// find data matching the key
	virtual std::optional<octet_vector> find(key_type const& key) const = 0;

	/// remove data associated with the key
	virtual void erase(key_type const& key) = 0;

	/// remove all data
	virtual void clear() = 0;
};

using key_value_access_ptr = std::shared_ptr<key_value_access>;

}
