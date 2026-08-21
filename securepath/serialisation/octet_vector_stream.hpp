// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

namespace securepath::serialisation {

class octet_span_istream {
public:
	octet_span_istream(octet_span);
	octet_span_istream(octet_span, std::size_t size);

	bool read(char* buf, std::size_t size);

protected:
	octet_span data_;
	std::size_t read_pos_;
	std::size_t size_;
};

class octet_vector_ostream {
public:
	octet_vector_ostream(octet_vector& vec); //the write pos is set to vec.size()
	octet_vector_ostream(octet_vector& vec, std::size_t write_pos);

	bool write(char const* buf, std::size_t size);
protected:
	octet_vector& vec_;
	std::size_t write_pos_;
};

class octet_vector_stream
	: octet_span_istream
	, octet_vector_ostream
{
public:
	octet_vector_stream(octet_vector& vec); //the write pos is set to vec.size()
	octet_vector_stream(octet_vector& vec, std::size_t write_pos);

	bool read(char* buf, std::size_t size);
	bool write(char const* buf, std::size_t size);
};

}

