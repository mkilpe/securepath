// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/hmac.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::crypto::test {

namespace {

void hmac_test(hash_algorithm hid) {
	octet_vector const key = random_octet_vector(16);
	octet_vector const data1 = random_octet_vector(512);
	octet_vector const data2 = random_octet_vector(512);
	REQUIRE(data1 != data2);

	mac_ptr m1 = create_hmac(hid, key);
	mac_ptr m2 = create_hmac(hid, key);

	octet_vector mac1 = m1->calculate(data1);
	octet_vector mac2 = m2->calculate(data2);
	CHECK(mac1.size() == hash_digest_size(hid));

	CHECK(m1->verify(data1, mac1));
	CHECK(!m1->verify(data1, mac2));
	CHECK(m2->verify(data2, mac2));
	CHECK(!m2->verify(data2, mac1));
	CHECK(!m2->verify(data2, octet_vector(mac2.begin(), mac2.end()-1)));
}

}

TEST_CASE("hmac_sha256 basic test", "[hmac_sha256][mac]") {
	octet_vector const key = random_octet_vector(16);
	octet_vector const data = random_octet_vector(512);

	mac_ptr m = create_hmac_sha256(key);
	CHECK(m->size() == 32);

	octet_vector mac(m->size());
	std::size_t calc = m->calculate(data.data(), data.data()+data.size(), mac.data());

	CHECK(calc == m->size());
	CHECK(m->verify(data.data(), data.data()+data.size(), mac.data()));
	CHECK(m->calculate(data) == mac);
	CHECK(m->calculate(data) == mac);
}

TEST_CASE("hmac algorithms", "[mac]") {
	hmac_test(hash_algorithm::sha256);
	hmac_test(hash_algorithm::sha512);
	hmac_test(hash_algorithm::sha3_256);
	hmac_test(hash_algorithm::sha3_512);
	CHECK_THROWS_AS(create_hmac(static_cast<hash_algorithm>(42), random_octet_vector(16)), unknown_hash_algorithm);
}

TEST_CASE("hmac known answer", "[mac][kat]") {
	// RFC 4231 test case 2
	octet_vector const key = {'J', 'e', 'f', 'e'};
	std::string const msg = "what do ya want for nothing?";
	octet_vector const data(msg.begin(), msg.end());
	CHECK(to_hex(create_hmac(hash_algorithm::sha256, key)->calculate(data)) == "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843");
}

}
