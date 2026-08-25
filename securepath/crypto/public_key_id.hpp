// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/types.hpp>

#include <format>
#include <functional>
#include <iosfwd>
#include <string>

namespace securepath::crypto {

class public_key;

/// SHA3-256 over the serialised public key material (suite and both key halves)
class public_key_id {
public:
	public_key_id() = default;
	public_key_id(public_key const&);
	explicit public_key_id(octet_vector id);
	/// construct public key id from hex encoded string (ie. generated with in_hex())
	explicit public_key_id(std::string const&);

	std::string in_hex() const;
	octet_vector const& data() const;

	bool is_valid() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & id_;
	}

private:
	octet_vector id_;
};

bool operator==(public_key_id const& l, public_key_id const& r);
bool operator!=(public_key_id const& l, public_key_id const& r);
bool operator<(public_key_id const& l, public_key_id const& r);
std::ostream& operator<<(std::ostream&, public_key_id const&);

}

namespace std {
	template<>
	struct hash<securepath::crypto::public_key_id> {
		std::size_t operator()(securepath::crypto::public_key_id const& id) const {
			return h_(id.data());
		}
	private:
		hash<securepath::octet_vector> h_;
	};

	template<>
	struct formatter<securepath::crypto::public_key_id> : formatter<std::string> {
		auto format(securepath::crypto::public_key_id const& id, format_context& ctx) const {
			return formatter<std::string>::format(id.in_hex(), ctx);
		}
	};
}
