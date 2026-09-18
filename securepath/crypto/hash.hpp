// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <securepath/serialisation/decls.hpp>
#include <securepath/util/span.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace Botan { class HashFunction; }

namespace securepath::crypto {

struct unknown_hash_algorithm : crypto_error { using crypto_error::crypto_error; };

/// values are part of the wire format, never renumber
enum class hash_algorithm : std::uint32_t {
	sha256 = 0,
	sha512 = 1,
	sha3_256 = 2,
	sha3_512 = 3
};

serialisation::serialiser& serialise(serialisation::serialiser& s, hash_algorithm const& v);
serialisation::deserialiser& serialise(serialisation::deserialiser& s, hash_algorithm& v);

std::size_t hash_digest_size(hash_algorithm = hash_algorithm::sha3_512);
octet_vector hash(octet_span data, hash_algorithm = hash_algorithm::sha3_512);

/// Incremental hashing for data that does not fit one span (streams, chunk lists).
/// final() returns the digest over everything since construction or the previous final()
class hash_stream {
public:
	explicit hash_stream(hash_algorithm = hash_algorithm::sha3_512);
	hash_stream(hash_stream&&) noexcept;
	hash_stream& operator=(hash_stream&&) noexcept;
	~hash_stream();

	void update(octet_span data);
	octet_vector final();
	std::size_t digest_size() const;
private:
	std::unique_ptr<Botan::HashFunction> impl_;
};

namespace detail {
/// Botan's name for the algorithm, throws unknown_hash_algorithm
std::string botan_hash_name(hash_algorithm);
}

}
