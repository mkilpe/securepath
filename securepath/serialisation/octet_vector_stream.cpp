// SPDX-License-Identifier: MIT

#include "octet_vector_stream.hpp"

#include <cassert>
#include <cstring>

namespace securepath::serialisation {

octet_span_istream::octet_span_istream(octet_span data)
: octet_span_istream(data, data.size())
{}

octet_span_istream::octet_span_istream(octet_span data, std::size_t size)
: data_(data)
, read_pos_()
, size_(size)
{}

bool octet_span_istream::read(char* buf, std::size_t size) {
	assert(buf);
	assert(size);
	bool ret = read_pos_ + size <= size_;
	if(ret) {
		std::memcpy(buf, data_.data()+read_pos_, size);
		read_pos_ += size;
	} else {
		read_pos_ = size_;
	}
	return ret;
}

octet_vector_ostream::octet_vector_ostream(octet_vector& vec)
: octet_vector_ostream(vec, vec.size())
{}

octet_vector_ostream::octet_vector_ostream(octet_vector& vec, std::size_t write_pos)
: vec_(vec)
, write_pos_(write_pos)
{}


bool octet_vector_ostream::write(char const* buf, std::size_t size) {
	if(buf && size) {
		// a write position past the end (constructed that way, or the vector
		// shrunk externally) must grow the vector, not underflow size_left
		if(write_pos_ > vec_.size()) {
			vec_.resize(write_pos_);
		}
		std::size_t size_left = vec_.size() - write_pos_;
		if(size_left < size) {
			vec_.resize(vec_.size()+size-size_left);
		}
		std::memcpy(&vec_[write_pos_], buf, size);
		write_pos_ += size;
	}
	return true;
}

octet_vector_stream::octet_vector_stream(octet_vector& vec)
: octet_vector_stream(vec, vec.size())
{}

octet_vector_stream::octet_vector_stream(octet_vector& vec, std::size_t write_pos)
: octet_span_istream(vec, write_pos)
, octet_vector_ostream(vec, write_pos)
{}

bool octet_vector_stream::read(char* buf, std::size_t size) {
	return octet_span_istream::read(buf, size);
}

bool octet_vector_stream::write(char const* buf, std::size_t size) {
	bool ret = octet_vector_ostream::write(buf, size);
	octet_span_istream::data_ = octet_span(octet_vector_ostream::vec_);
	octet_span_istream::size_ = octet_vector_ostream::write_pos_;
	return ret;
}

}
