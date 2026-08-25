// SPDX-License-Identifier: MIT

#include "version_number.hpp"

#include <ostream>
#include <tuple>

namespace securepath {

version_number::version_number(std::uint16_t major, std::uint16_t minor, std::uint16_t build, std::string rev)
: major_(major)
, minor_(minor)
, build_(build)
, revision_(std::move(rev))
{}

std::string version_number::to_string() const {
	std::string ret = std::to_string(major_) + "." + std::to_string(minor_) + "." + std::to_string(build_);
	if(!revision_.empty()) {
		ret += " (" + revision_ + ")";
	}
	return ret;
}

bool operator<(version_number const& l, version_number const& r) {
	return std::forward_as_tuple(l.major(), l.minor(), l.build(), l.revision())
		< std::forward_as_tuple(r.major(), r.minor(), r.build(), r.revision());
}

bool operator==(version_number const& l, version_number const& r) {
	return l.major() == r.major() && l.minor() == r.minor()
		&& l.build() == r.build() && l.revision() == r.revision();
}

bool operator<=(version_number const& l, version_number const& r) {
	return l < r || l == r;
}

bool operator>(version_number const& l, version_number const& r) {
	return !(l <= r);
}

bool operator>=(version_number const& l, version_number const& r) {
	return !(l < r);
}

bool operator!=(version_number const& l, version_number const& r) {
	return !(l == r);
}

std::ostream& operator<<(std::ostream& out, version_number const& v) {
	return out << v.to_string();
}

}

