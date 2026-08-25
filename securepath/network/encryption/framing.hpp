// SPDX-License-Identifier: MIT

#pragma once

#include "tls_stream.hpp"

#include <securepath/util/span.hpp>
#include <securepath/util/types.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <system_error>

namespace securepath::network {

/// Record framing on top of tls_stream: u32 big-endian payload length followed by the payload.
/// Message boundaries are preserved, a frame is at most max_frame_size bytes of payload.
constexpr std::size_t max_frame_size{16u * 1024 * 1024};
constexpr std::size_t frame_header_size{4};

using frame_send_handler = std::function<void(std::error_code)>;
using frame_receive_handler = std::function<void(std::error_code, octet_vector)>;

/// Encode the header in front of the payload (for callers that build frames themselves)
octet_vector encode_frame(octet_span payload);
/// Decode a header; returns the payload length (unchecked against max_frame_size)
std::uint32_t decode_frame_length(std::span<std::uint8_t const, frame_header_size> header);

/// Send one frame; errc::invalid_data if the payload exceeds max_frame_size. Handlers run on the stream's strand.
void async_send_frame(std::shared_ptr<tls_stream> const& stream, octet_span payload, frame_send_handler handler);

/**
 * Receives whole frames from a tls_stream. One outstanding receive at a time; the reader must
 * outlive the operation (typically it is a member next to the stream). Frames larger than
 * max_frame_size fail with errc::invalid_record.
 */
class frame_reader {
public:
	explicit frame_reader(std::shared_ptr<tls_stream> stream);

	frame_reader(frame_reader const&) = delete;
	frame_reader& operator=(frame_reader const&) = delete;

	void async_receive_frame(frame_receive_handler handler);

private:
	void read_more();
	void on_read(std::error_code ec, std::size_t bytes);
	void complete(std::error_code ec);

private:
	std::shared_ptr<tls_stream> stream_;
	frame_receive_handler handler_;
	octet_vector buffer_;
	std::size_t received_{};
	std::size_t expected_{frame_header_size};
	bool header_done_{};
	bool busy_{};
};

}
