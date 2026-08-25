// SPDX-License-Identifier: MIT

#include "framing.hpp"

#include <asio/post.hpp>

#include <utility>

namespace securepath::network {

octet_vector encode_frame(octet_span payload) {
	auto size = static_cast<std::uint32_t>(payload.size());
	octet_vector frame;
	frame.reserve(frame_header_size + payload.size());
	frame.push_back(static_cast<std::uint8_t>(size >> 24));
	frame.push_back(static_cast<std::uint8_t>(size >> 16));
	frame.push_back(static_cast<std::uint8_t>(size >> 8));
	frame.push_back(static_cast<std::uint8_t>(size));
	frame.insert(frame.end(), payload.begin(), payload.end());
	return frame;
}

std::uint32_t decode_frame_length(std::span<std::uint8_t const, frame_header_size> header) {
	return (std::uint32_t{header[0]} << 24) | (std::uint32_t{header[1]} << 16)
		| (std::uint32_t{header[2]} << 8) | std::uint32_t{header[3]};
}

void async_send_frame(std::shared_ptr<tls_stream> const& stream, octet_span payload, frame_send_handler handler) {
	if(payload.size() > max_frame_size) {
		asio::post(stream->strand(), [handler = std::move(handler)] { handler(make_error_code(errc::invalid_data)); });
		return;
	}
	stream->async_write(encode_frame(payload), [handler = std::move(handler)](std::error_code ec, std::size_t) {
		handler(ec);
	});
}

frame_reader::frame_reader(std::shared_ptr<tls_stream> stream)
: stream_(std::move(stream))
, buffer_(frame_header_size)
{
}

void frame_reader::async_receive_frame(frame_receive_handler handler) {
	if(busy_) {
		asio::post(stream_->strand(), [handler = std::move(handler)] {
			handler(std::make_error_code(std::errc::operation_in_progress), {});
		});
		return;
	}
	busy_ = true;
	handler_ = std::move(handler);
	received_ = 0;
	expected_ = frame_header_size;
	header_done_ = false;
	buffer_.resize(frame_header_size);
	read_more();
}

void frame_reader::read_more() {
	std::span<std::uint8_t> target(buffer_.data() + received_, expected_ - received_);
	stream_->async_read_some(target, [this](std::error_code ec, std::size_t bytes) {
		on_read(ec, bytes);
	});
}

void frame_reader::on_read(std::error_code ec, std::size_t bytes) {
	if(ec) {
		complete(ec);
		return;
	}
	received_ += bytes;
	if(received_ < expected_) {
		read_more();
		return;
	}
	if(header_done_) {
		complete({});
		return;
	}
	std::size_t length = decode_frame_length(std::span<std::uint8_t const, frame_header_size>(buffer_.data(), frame_header_size));
	if(length > max_frame_size) {
		complete(make_error_code(errc::invalid_record));
		return;
	}
	header_done_ = true;
	received_ = 0;
	expected_ = length;
	buffer_.resize(length);
	if(length == 0) {
		complete({});
	} else {
		read_more();
	}
}

void frame_reader::complete(std::error_code ec) {
	busy_ = false;
	auto handler = std::exchange(handler_, nullptr);
	octet_vector payload;
	if(!ec) {
		payload.swap(buffer_);
	}
	handler(ec, std::move(payload));
}

}
