// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/serialisation/codec/asn_der/buffered_stream.hpp>

#include <sstream>

namespace securepath::serialisation::test {

TEST_CASE("buffered_stream exception") {
	std::stringstream ss;
	buffered_stream buf_stream(ss);
	octet_vector o = securepath::test::random_octet_vector(20);

	CHECK_THROWS_AS(buf_stream.read(o.data(), o.size()), std::exception);
}


TEST_CASE("buffered_stream") {
	std::string data = securepath::test::random_string(50);
	std::stringstream ss(data);
	buffered_stream stream(ss);

	octet_vector buf = securepath::test::random_octet_vector(20);

	CHECK(stream.pos() == 0);

	{
		auto res = stream.read(buf.data(), buf.size());
		CHECK(res == buf.size());
		CHECK(buf == subbuffer(to_octet_vector(data), 0, buf.size()));
	}

	CHECK(stream.pos() == buf.size());

	{
		stream_peek_guard guard(stream);
		auto res = stream.read(buf.data(), buf.size());
		CHECK(res == buf.size());
		CHECK(buf == subbuffer(to_octet_vector(data), buf.size(), buf.size()));
		CHECK(stream.pos() == 2*buf.size());
	}

	CHECK(stream.pos() == buf.size());

	CHECK(stream.readable_bytes(10));
	CHECK(stream.readable_bytes(30));

	CHECK(stream.pos() == buf.size());

	{
		auto res = stream.read(buf.data(), buf.size());
		CHECK(res == buf.size());
		CHECK(buf == subbuffer(to_octet_vector(data), buf.size(), buf.size()));
	}

	CHECK(stream.pos() == 2*buf.size());

	CHECK(stream.readable_bytes(10));
	CHECK(!stream.readable_bytes(11));
}

TEST_CASE("buffered_stream read spans look-ahead buffer and stream", "[buffered_stream]") {
	// readable_bytes buffers bytes ahead; a read crossing from that buffer
	// into the live stream must report the full count, not just the stream part
	std::string data = securepath::test::random_string(30);
	std::stringstream ss(data);
	buffered_stream stream(ss);

	CHECK(stream.readable_bytes(10)); // 10 bytes now buffered

	octet_vector buf(25);
	auto res = stream.read(buf.data(), buf.size());
	CHECK(res == buf.size());
	CHECK(buf == subbuffer(to_octet_vector(data), 0, buf.size()));
	CHECK(stream.pos() == buf.size());
}

}
