// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/database/connection.hpp>

namespace securepath::database::sqlite {

connection_ptr create_sqlite_connection(std::string const& file);
void set_to_wal_mode(connection_ptr);

}

