// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/hash.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::crypto::test {

namespace {

std::vector<hash_algorithm> const algorithms = {hash_algorithm::sha256, hash_algorithm::sha512, hash_algorithm::sha3_256, hash_algorithm::sha3_512};

bool repeat_test(octet_vector const& o, hash_algorithm id) {
	octet_vector r1 = hash(o, id);
	octet_vector r2 = hash(o, id);
	return r1 == r2 && r1.size() == hash_digest_size(id);
}

bool same_hash(octet_vector const& o1, octet_vector const& o2, hash_algorithm id) {
	return hash(o1, id) == hash(o2, id);
}

}

TEST_CASE("hash_basic_test", "[hash]") {
	octet_vector const o1 = random_octet_vector(32);
	octet_vector const o2 = random_octet_vector(32);
	for(auto id : algorithms) {
		CHECK(repeat_test(o1, id));
		CHECK(!same_hash(o1, o2, id));
	}
}

TEST_CASE("hash sizes", "[hash]") {
	CHECK(hash_digest_size(hash_algorithm::sha256) == 32);
	CHECK(hash_digest_size(hash_algorithm::sha512) == 64);
	CHECK(hash_digest_size(hash_algorithm::sha3_256) == 32);
	CHECK(hash_digest_size(hash_algorithm::sha3_512) == 64);
	CHECK(hash_digest_size() == 64);
}

TEST_CASE("hash empty, single and big", "[hash]") {
	for(std::size_t size : {0u, 1u, 10000u}) {
		octet_vector const o = random_octet_vector(size);
		for(auto id : algorithms) {
			CHECK(repeat_test(o, id));
		}
	}
}

TEST_CASE("hash known answers", "[hash][kat]") {
	octet_vector const abc = {'a', 'b', 'c'};
	CHECK(to_hex(hash(abc, hash_algorithm::sha256)) == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
	CHECK(to_hex(hash(abc, hash_algorithm::sha512)) == "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F");
	CHECK(to_hex(hash(abc, hash_algorithm::sha3_256)) == "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532");
	CHECK(to_hex(hash(abc, hash_algorithm::sha3_512)) == "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0");
}

TEST_CASE("invalid hash algorithm", "[hash]") {
	octet_vector const o = random_octet_vector(32);
	CHECK_THROWS_AS(hash(o, static_cast<hash_algorithm>(678)), unknown_hash_algorithm);
	CHECK_THROWS_AS(hash_digest_size(static_cast<hash_algorithm>(678)), unknown_hash_algorithm);
}

TEST_CASE("hash algorithm serialisation", "[hash][serialisation]") {
	for(auto id : algorithms) {
		auto ser = serialisation::asn_der_serialise(id);
		CHECK(serialisation::asn_der_deserialise<hash_algorithm>(ser) == id);
	}
}

}
