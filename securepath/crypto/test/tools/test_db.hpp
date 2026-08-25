// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/database/sqlite/connection.hpp>

#include <cstdio>
#include <string>

namespace securepath::crypto::test {

/// sqlite database file in the working directory (the build tree under ctest) that is removed before and after use
struct scoped_test_db {
	explicit scoped_test_db(std::string name)
	: path("crypto_test_" + std::move(name) + ".sqlite")
	{
		std::remove(path.c_str());
	}

	~scoped_test_db() {
		std::remove(path.c_str());
	}

	scoped_test_db(scoped_test_db const&) = delete;
	scoped_test_db& operator=(scoped_test_db const&) = delete;

	database::connection_ptr connect() const {
		return database::sqlite::create_sqlite_connection(path);
	}

	std::string path;
};

}
