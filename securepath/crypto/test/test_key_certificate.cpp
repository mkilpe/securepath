// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/key_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

#include <format>

namespace securepath::crypto::test {

TEST_CASE("key_certificate basic test", "[key_certificate][certificate_data]") {
	private_key key1 = generate_private_key();
	private_key key2 = generate_private_key();
	auto cert1 = create_key_certificate(key1, key2.public_key(), 0);
	auto cert2 = create_key_certificate(key1, key2.public_key(), 3, key_cert_restriction().hostname("test.com"), random_octet_vector(8));
	auto cert3 = create_key_certificate(key2, key1.public_key(), 0);
	CHECK(cert1.verify_me(key1.public_key()));
	CHECK(cert2.verify_me(key1.public_key()));
	CHECK(cert3.verify_me(key2.public_key()));
	CHECK(!cert1.verify_me(key2.public_key()));
	CHECK(!cert3.verify_me(key1.public_key()));
	CHECK(cert1.type() == key_certificate_data::id);
	CHECK(cert1.id().is_valid());
	auto data1 = cert1.extract<key_certificate_data>();
	auto data2 = cert2.extract<key_certificate_data>();
	auto data3 = cert3.extract<key_certificate_data>();
	CHECK(data1.subject() == key2.public_key());
	CHECK(data2.subject() == key2.public_key());
	CHECK(data3.subject() == key1.public_key());
	CHECK(data2.restrictions().hostname() == "test.com");
	CHECK(data1.ca_level() == 0);
	CHECK(data2.ca_level() == 3);
	CHECK(data3.ca_level() == 0);
	CHECK(data1.metadata().empty());
	CHECK(data2.metadata().size() == 8);
	CHECK(securepath::test::check_serialisation_without_compare(data1));
	CHECK(securepath::test::check_serialisation_without_compare(data2));
	CHECK(securepath::test::check_serialisation(cert1));
	CHECK(securepath::test::check_serialisation(cert2));
}

TEST_CASE("key_certificate restriction basic test", "[key_certificate][certificate_data]") {
	key_cert_restriction r1, r2, r3, r4, empty;
	r1.hostname("test.org");
	r2.hostname(".test.org");
	r3.hostname("sub.test.org");
	r4.hostname("est.org");
	CHECK(r1.is_subset_of(r1));
	CHECK(r2.is_subset_of(r1));
	CHECK(r3.is_subset_of(r1));
	CHECK(!r4.is_subset_of(r1));
	CHECK(r2.is_subset_of(r2));
	CHECK(r3.is_subset_of(r2));
	CHECK(!r4.is_subset_of(r2));
	CHECK(!r4.is_subset_of(r3));
	CHECK(!r1.is_subset_of(r3));
	CHECK(!r2.is_subset_of(r3));
	CHECK(!r4.is_subset_of(r3));
	CHECK(!r1.is_subset_of(r4));
	CHECK(!r2.is_subset_of(r4));
	CHECK(!r3.is_subset_of(r4));
	CHECK(merge(r1, r2) == r2);
	CHECK(merge(r1, r3) == r3);
	CHECK(merge(r2, r1) == r2);
	CHECK(merge(r3, r1) == r3);
	CHECK(merge(r2, r3) == r3);
	CHECK(merge(r3, r2) == r3);
	CHECK_THROWS(merge(r1, r4));
	CHECK_THROWS(merge(r2, r4));
	CHECK_THROWS(merge(r3, r4));
	CHECK(r1.is_subset_of(empty));
	CHECK(!empty.is_subset_of(r1));
	CHECK(merge(r1, empty) == r1);
	CHECK(merge(empty, r1) == r1);
}

TEST_CASE("key_certificate restriction is case insensitive and formats", "[key_certificate][certificate_data][security]") {
	key_cert_restriction upper, lower, sub;
	upper.hostname("TEST.ORG");
	lower.hostname("test.org");
	sub.hostname("Sub.Test.Org");
	CHECK(upper.is_subset_of(lower));
	CHECK(lower.is_subset_of(upper));
	CHECK(sub.is_subset_of(upper));
	CHECK(!upper.is_subset_of(sub));
	CHECK(upper != lower); // equality is literal, subset is case insensitive
	CHECK(std::format("{}", sub) == "[hostname: Sub.Test.Org]");
	CHECK(securepath::test::check_serialisation_without_compare(sub));
}

}
