// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/sequence.hpp>
#include <securepath/util/types.hpp>

#include <format>
#include <functional>
#include <iosfwd>
#include <string>

namespace securepath::crypto {

class certificate_id {
public:
	certificate_id() = default;
	explicit certificate_id(octet_vector id);
	/// construct from hex encoded string (ie. in_hex())
	explicit certificate_id(std::string const&);

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

bool operator==(certificate_id const& l, certificate_id const& r);
bool operator!=(certificate_id const& l, certificate_id const& r);
bool operator<(certificate_id const& l, certificate_id const& r);
std::ostream& operator<<(std::ostream&, certificate_id const&);

}

namespace std {
	template<>
	struct hash<securepath::crypto::certificate_id> {
		std::size_t operator()(securepath::crypto::certificate_id const& id) const {
			return h_(id.data());
		}
	private:
		hash<securepath::octet_vector> h_;
	};

	template<>
	struct formatter<securepath::crypto::certificate_id> : formatter<std::string> {
		auto format(securepath::crypto::certificate_id const& id, format_context& ctx) const {
			return formatter<std::string>::format(id.in_hex(), ctx);
		}
	};
}
