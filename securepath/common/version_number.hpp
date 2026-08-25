// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/serialisation/sequence.hpp>

#include <cstdint>
#include <string>
#include <iosfwd>

namespace securepath {

/**
 * Represents a product version number
 */

class version_number {
public:
	version_number(std::uint16_t major = 0, std::uint16_t minor = 0, std::uint16_t build = 0, std::string rev = {});

	std::uint16_t major() const { return major_; }
	std::uint16_t minor() const { return minor_; }
	std::uint16_t build() const { return build_; }
	std::string revision() const { return revision_; }

	std::string to_string() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & major_ & minor_ & build_ & revision_;
	}

private:
	std::uint16_t major_;
	std::uint16_t minor_;
	std::uint16_t build_;
	std::string revision_;
};

bool operator<(version_number const& l, version_number const& r);
bool operator==(version_number const& l, version_number const& r);
bool operator<=(version_number const& l, version_number const& r);
bool operator>(version_number const& l, version_number const& r);
bool operator>=(version_number const& l, version_number const& r);
bool operator!=(version_number const& l, version_number const& r);

std::ostream& operator<<(std::ostream& out, version_number const&);
}

