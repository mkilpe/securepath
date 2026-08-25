// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/infrastructure/packet_transport/protocol/types.hpp>
#include <securepath/database/connection.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>

namespace securepath::packet_transport {

using packet_notify_type = std::function<void(crypto::public_key_id const&, ack_type)>;

struct queued_packet {
	crypto::public_key_id const receiver;
	transport_payload const packet;
	packet_notify_type const notify;
	ack_type const ack{};
	ack_type const sender_ack{};
	crypto::public_key_id const sender;
	std::atomic_flag remove_flag{}; //set if the packet was acked already or the queued_packet is disposed
};

class packet_storage;

class packet_handle {
public:
	packet_handle(packet_storage&, ack_type, std::shared_ptr<queued_packet> const&);

	ack_type ack() const;
	void mark_as_acked();

private:
	packet_storage* storage_{};
	ack_type ack_{};
	std::weak_ptr<queued_packet> packet_;
};

struct index_packet {
	ack_type ack{};
	std::weak_ptr<queued_packet> packet;
};

struct stored_packet {
	packet_handle handle;
	transport_payload packet;
};

class packet_storage {
public:
	packet_storage(database::connection_ptr);
	~packet_storage();

	/// Close the database thread and purge queues to database (this might take little while)
	void close();

	/// Insert package to the storage
	packet_handle insert(crypto::public_key_id receiver,
		transport_payload,
		ack_type sender_ack,
		crypto::public_key_id sender,
		packet_notify_type);

	/// Remove package from the storage when acked, should not use this directly but the packet_handle::mark_as_acked
	void remove(ack_type ack, std::weak_ptr<queued_packet> const&);

	/// Get packets not yet acked for user
	std::deque<stored_packet> get_pending_packets(crypto::public_key_id const& receiver);

private:
	void thread_entry();
	bool next_packet(std::shared_ptr<queued_packet>&, ack_type& remove_ack);
	bool write_to_database(std::shared_ptr<queued_packet> const&);
	void remove_from_database(ack_type);
	void remove_from_index(crypto::public_key_id const& id, ack_type ack);
	void purge_queues();

	packet_storage(packet_storage const&) = delete;

private:
	database::connection_ptr db_;

	mutable std::mutex queue_mutex_;

	std::condition_variable cond_;
	bool close_{};
	std::int64_t sequence_{};

	std::deque<std::shared_ptr<queued_packet>> queue_;
	std::deque<ack_type> remove_queue_;
	std::unordered_multimap<crypto::public_key_id, index_packet> receiver_index_;

	std::optional<database::prepared_statement> insert_statement_;

	std::thread thread_;
};

}
