// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/test_frame/test_suite.hpp>

#include <securepath/crypto/certificate.hpp>
#include <securepath/crypto/identifier_certificate.hpp>
#include <securepath/crypto/key_generation.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

namespace securepath::crypto::test {

template<typename Find, typename Remove, typename Search>
void certificate_access_empty_test(Find find_func, Remove remove_func, Search search_func) {
	auto key = generate_private_key();
	certificate cert;
	cert.sign_me(key);
	CHECK_NOTHROW(remove_func(cert.id()));
	CHECK(find_func(cert.id()) == std::nullopt);
	CHECK((search_func("hop")).empty());
}

template<typename Find, typename Insert, typename Remove>
void certificate_access_find_insert_remove_test_1(Find find_func, Insert insert_func, Remove remove_func) {
	auto key1 = generate_private_key();
	auto key2 = generate_private_key();
	certificate cert1;
	cert1.sign_me(key1);
	certificate cert2;
	cert2.sign_me(key2);
	certificate cert3;
	cert3.sign_me(key1);
	insert_func(cert1);
	insert_func(cert2);
	auto ret1 = find_func(cert1.id());
	auto ret2 = find_func(cert2.id());
	auto ret3 = find_func(cert3.id());
	REQUIRE(ret1);
	REQUIRE(ret2);
	CHECK(ret3 == std::nullopt);
	CHECK(ret1.value().verify_me(key1.public_key()));
	CHECK(!ret1.value().verify_me(key2.public_key()));
	CHECK(ret2.value().verify_me(key2.public_key()));
	CHECK(!ret2.value().verify_me(key1.public_key()));
	remove_func(cert1.id());
	remove_func(cert2.id());
	CHECK(find_func(cert1.id()) == std::nullopt);
	CHECK(find_func(cert2.id()) == std::nullopt);
}

template<typename Find, typename Insert, typename Remove, typename Search>
void certificate_access_duplicate_test_1(Find find_func, Insert insert_func, Remove remove_func, Search search_func) {
	auto key = generate_private_key();
	std::string identifier = "hop1";
	certificate cert1 = create_identifier_certificate(key, identifier);
	certificate cert2 = create_identifier_certificate(key, identifier);
	REQUIRE(cert1.id() != cert2.id());
	insert_func(cert1);
	insert_func(cert1);
	insert_func(cert2);
	REQUIRE(find_func(cert1.id()) != std::nullopt);
	CHECK(int(search_func(identifier).size()) == 2);
	remove_func(cert1.id());
	CHECK(int(search_func(identifier).size()) == 1);
	remove_func(cert2.id());
	CHECK((int)search_func(identifier).size() == 0);
	CHECK(find_func(cert1.id()) == std::nullopt);
}

template<typename Find, typename Insert, typename Remove, typename Search>
void certificate_access_search_identifier_test_1(Find find_func, Insert insert_func, Remove remove_func, Search search_func) {
	auto key = generate_private_key();
	certificate cert1;
	cert1.sign_me(key);
	std::string identifier1 = "hop1";
	std::string identifier2 = "hop2";
	std::string empty_identifier = "";
	certificate cert2 = create_identifier_certificate(key, identifier1);
	certificate cert3 = create_identifier_certificate(key, identifier1);
	certificate cert4 = create_identifier_certificate(key, identifier2);
	CHECK(search_func(identifier1).empty());
	insert_func(cert1);
	REQUIRE(find_func(cert1.id()) != std::nullopt);
	CHECK(search_func(identifier1).empty());
	CHECK(search_func(empty_identifier).empty());
	insert_func(cert2);
	REQUIRE(find_func(cert2.id()) != std::nullopt);
	CHECK(search_func(identifier2).empty());
	CHECK(search_func(empty_identifier).empty());
	insert_func(cert3);
	REQUIRE(find_func(cert3.id()) != std::nullopt);
	insert_func(cert4);
	REQUIRE(find_func(cert4.id()) != std::nullopt);
	std::vector<certificate> res1 = search_func(identifier1);
	std::vector<certificate> res2 = search_func(identifier2);
	CHECK(search_func(empty_identifier).empty());
	REQUIRE(int(res1.size()) == 2);
	REQUIRE(int(res2.size()) == 1);
	CHECK(res2[0].id() == cert4.id());
	std::vector<certificate_id> ids = {res1[0].id(), res1[1].id()};
	CHECK(std::find(ids.begin(), ids.end(), cert2.id()) != ids.end());
	CHECK(std::find(ids.begin(), ids.end(), cert3.id()) != ids.end());
	remove_func(cert2.id());
	remove_func(cert3.id());
	CHECK(search_func(identifier1).empty());
	CHECK(!search_func(identifier2).empty());
}

}
