// SPDX-License-Identifier: MIT

#include "public_key_id.hpp"

#include "public_key.hpp"

#include <securepath/util/conversions.hpp>

#include <ostream>

namespace securepath::crypto {

public_key_id::public_key_id(public_key const& k)
: public_key_id(k.id())
{
}

public_key_id::public_key_id(octet_vector id)
: id_(std::move(id))
{
}

public_key_id::public_key_id(std::string const& id)
: id_(securepath::from_hex(id))
{
}

std::string public_key_id::in_hex() const {
	return securepath::to_hex(id_);
}

octet_vector const& public_key_id::data() const {
	return id_;
}

bool public_key_id::is_valid() const {
	return !id_.empty();
}

bool operator==(public_key_id const& l, public_key_id const& r) {
	return l.data() == r.data();
}

bool operator!=(public_key_id const& l, public_key_id const& r) {
	return !(l == r);
}

bool operator<(public_key_id const& l, public_key_id const& r) {
	return l.data() < r.data();
}

std::ostream& operator<<(std::ostream& out, public_key_id const& kid) {
	return out << kid.in_hex();
}

}
