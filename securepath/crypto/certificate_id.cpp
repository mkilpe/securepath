// SPDX-License-Identifier: MIT

#include "certificate_id.hpp"

#include <securepath/util/conversions.hpp>

#include <ostream>

namespace securepath::crypto {

certificate_id::certificate_id(octet_vector id)
: id_(std::move(id))
{
}

certificate_id::certificate_id(std::string const& id)
: id_(securepath::from_hex(id))
{
}

std::string certificate_id::in_hex() const {
	return securepath::to_hex(id_);
}

octet_vector const& certificate_id::data() const {
	return id_;
}

bool certificate_id::is_valid() const {
	return !id_.empty();
}

bool operator==(certificate_id const& l, certificate_id const& r) {
	return l.data() == r.data();
}

bool operator!=(certificate_id const& l, certificate_id const& r) {
	return !(l == r);
}

bool operator<(certificate_id const& l, certificate_id const& r) {
	return l.data() < r.data();
}

std::ostream& operator<<(std::ostream& o, certificate_id const& cert) {
	return o << cert.in_hex();
}

}
