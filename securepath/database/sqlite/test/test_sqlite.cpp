// SPDX-License-Identifier: MIT

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/test_frame/test_suite.hpp>

#include <cstdio>
#include <iostream>

namespace securepath::database::sqlite {
namespace test {

TEST_CASE("sqlite basic test", "[sqlite][database]") {

	std::remove("test.db");
	connection_ptr db = create_sqlite_connection("test.db");
	db->prepare("CREATE TABLE test(a INTEGER);").execute();
	db->prepare("INSERT INTO test VALUES (8);").execute();
	auto ps1 = db->prepare("INSERT INTO test VALUES (:ph);");
	ps1.bind(":ph", std::int64_t(5));
	ps1.execute();

	CHECK(ps1.last_inserted_row_id() == 2);

	auto ps2 = db->prepare("SELECT * FROM test;");
	auto res = ps2.execute();
	REQUIRE(res);

	std::vector<std::int64_t> data;
	for(; res; res.next()) {
		data.push_back(*res.value<std::int64_t>(0));
	}
	std::vector<std::int64_t> expected = {8, 5};
	CHECK(data == expected);

	auto ps3 = db->prepare("SELECT count(*) FROM test;");
	auto res2 = ps3.execute();
	REQUIRE(res2);
	CHECK(*res2.value<std::int64_t>(0) == 2);

	std::remove("test.db");
}

TEST_CASE("sqlite bind value test", "[sqlite][database]") {

	std::remove("test.db");
	connection_ptr db = create_sqlite_connection("test.db");
	db->prepare("CREATE TABLE test(a INTEGER, b INTEGER, c STRING, d BLOB, e INTEGER);").execute();
	std::int64_t a = 3;
	std::uint64_t b = 9;
	std::string c = "test";
	octet_vector d(5, 'A');
	time_point e = time_point::clock::now();
	auto insert_st = db->prepare("INSERT INTO test VALUES(:a, :b, :c, :d, :e);");
	insert_st.bind(":a", a);
	insert_st.bind(":b", b);
	insert_st.bind(":c", c);
	insert_st.bind(":d", d);
	insert_st.bind(":e", e);
	insert_st.execute();

	auto select_st = db->prepare("SELECT * from test;");
	auto res = select_st.execute();
	REQUIRE(res);
	CHECK(res.value<std::int64_t>(0) == a);
	CHECK(res.value<std::uint64_t>(1) == b);
	CHECK(res.value<std::string>(2) == c);
	CHECK(res.value<octet_vector>(3) == d);
	CHECK(*res.value<time_point>(4) == std::chrono::time_point_cast<std::chrono::seconds>(e) );

	std::remove("test.db");
}

TEST_CASE("sqlite multiple connections test 1", "[sqlite][database]") {
	std::remove("test.db");;

	connection_ptr db1 = create_sqlite_connection("test.db");
	connection_ptr db2 = create_sqlite_connection("test.db");

	std::uint64_t n1 = 2;
	std::uint64_t n2 = 3;
	std::string k1 = "first";

	std::string find_st = "SELECT * FROM ttt WHERE key = :k LIMIT 1";
	std::string insert_st = "INSERT OR REPLACE INTO ttt VALUES(:k, :n)";

	db1->prepare("CREATE TABLE ttt(key TEXT PRIMARY KEY, number INTEGER)").execute();

	auto q0 = db1->prepare(insert_st);
	q0.bind(":k", k1);
	q0.bind(":n", n1);
	q0.execute();

	{// exception in case these braces are removed. Read the NOTE below
		auto q1 = db2->prepare(find_st);
		q1.bind(":k", k1);
		auto res1 = q1.execute();

		REQUIRE(res1);
		CHECK(res1.value<std::uint64_t>(1) == n1);
	}

	auto q2 = db1->prepare(insert_st);
	q2.bind(":k", k1);
	q2.bind(":n", n2);
	q2.execute();
	/* NOTE: exception in previous line if the braces above are removed
		connection.cpp:112	Failed to step: database is locked
		connection.cpp:86	Failed to destroy prepared statement (database is locked)

		But if changing the the q2 to
			auto q2 = db1->prepare(find_st);
			q2.bind(":k", k1);
			auto res22 = q2.execute();
		there is no exception even if removing braces

		Also, if changing db2 to db1 inside braces and remove braces it works normally.
	*/

	auto q3 = db2->prepare(find_st);
	q3.bind(":k", k1);
 	auto res2 = q3.execute();

	REQUIRE(res2);
	CHECK(res2.value<std::uint64_t>(1) == n2);

	std::remove("test.db");

}


TEST_CASE("sqlite transaction test", "[sqlite][database]") {
	std::remove("test.db");;

	connection_ptr db = create_sqlite_connection("test.db");
	{
		database::transaction t(*db);
	}
	try {
		database::transaction t(*db);
		throw 1;
	} catch(...) {}
}

}
}
