// SPDX-License-Identifier: MIT

#pragma once

#include "connection.hpp"
#include "types.hpp"

#include <securepath/serialisation/util.hpp>

namespace securepath::database {

template<typename Type>
Type extract_column_type(query const& q, std::size_t column) {
	octet_vector blob;
	if(!q.value(column, blob)) {
		throw database_error("failed to extract column as blob");
	}
	return serialisation::asn_der_deserialise<Type>(blob);
}

}

