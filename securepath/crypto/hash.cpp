// SPDX-License-Identifier: MIT

#include "hash.hpp"

#include <securepath/serialisation/enum.hpp>

#include <botan/hash.h>

namespace securepath::crypto {

namespace detail {

std::string botan_hash_name(hash_algorithm id) {
	std::string ret;
	if(id == hash_algorithm::sha256) {
		ret = "SHA-256";
	} else if(id == hash_algorithm::sha512) {
		ret = "SHA-512";
	} else if(id == hash_algorithm::sha3_256) {
		ret = "SHA-3(256)";
	} else if(id == hash_algorithm::sha3_512) {
		ret = "SHA-3(512)";
	} else {
		throw unknown_hash_algorithm();
	}
	return ret;
}

}

serialisation::serialiser& serialise(serialisation::serialiser& s, hash_algorithm const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, hash_algorithm& v) {
	return securepath::serialisation::serialise(s, v);
}

std::size_t hash_digest_size(hash_algorithm id) {
	return Botan::HashFunction::create_or_throw(detail::botan_hash_name(id))->output_length();
}

octet_vector hash(octet_span data, hash_algorithm id) {
	auto h = Botan::HashFunction::create_or_throw(detail::botan_hash_name(id));
	octet_vector ret(h->output_length());
	h->update(data.data(), data.size());
	h->final(ret.data());
	return ret;
}

}
