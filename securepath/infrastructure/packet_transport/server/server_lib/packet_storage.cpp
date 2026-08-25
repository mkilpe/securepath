// SPDX-License-Identifier: MIT

#include "packet_storage.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/timer.hpp>

#include <algorithm>

namespace securepath::packet_transport {

packet_handle::packet_handle(packet_storage& s, ack_type ack, std::shared_ptr<queued_packet> const& p)
: storage_(&s)
, ack_(ack)
, packet_(p)
{
}

ack_type packet_handle::ack() const {
	return ack_;
}

void packet_handle::mark_as_acked() {
	storage_->remove(ack_, packet_);
}

packet_storage::packet_storage(database::connection_ptr db)
: db_(db)
, thread_([&]{thread_entry();})
{
	if(!db_->has_table("packets")) {
		std::string prepare_str =
			"CREATE TABLE packets("
				"ack INTEGER PRIMARY KEY, "
				"receiver BLOB, "
				"packet BLOB,"
				"time INTEGER);";
		db_->prepare(prepare_str).execute();
		db_->prepare("CREATE INDEX receiver_index ON packets(receiver);").execute();
	}

	auto q = db_->prepare("SELECT max(ack) FROM packets;");
	auto res = q.execute();
	if(res) {
		sequence_ = res.value<std::int64_t>(0).value_or(0);
	}

	insert_statement_.emplace(db_->prepare("INSERT INTO packets(ack, receiver, packet, time) VALUES(:a, :r, :p, :t)"));
}

packet_storage::~packet_storage() {
	close();
}

void packet_storage::close() {
	{
		std::unique_lock l{queue_mutex_};
		close_ = true;
	}
	cond_.notify_one();
	if(thread_.joinable()) {
		thread_.join();
	}
	purge_queues();
}

packet_handle packet_storage::insert( crypto::public_key_id receiver
	, transport_payload packet
	, ack_type sender_ack
	, crypto::public_key_id sender
	, packet_notify_type notify)
{
	std::unique_lock l{queue_mutex_};
	auto p = std::make_shared<queued_packet>(
		std::move(receiver),
		std::move(packet),
		std::move(notify),
		++sequence_,
		sender_ack,
		std::move(sender));
	packet_handle ret{*this, p->ack, p};
	receiver_index_.insert(std::make_pair(p->receiver, index_packet{p->ack, p}));
	queue_.push_back(std::move(p));
	cond_.notify_one();
	return ret;
}

void packet_storage::remove(ack_type ack, std::weak_ptr<queued_packet> const& p) {
	bool flag = true;
	auto q_p = p.lock();
	if(q_p) {
		// if the flag was set to true already, the queue_packet is about to be disposed
		// and we should still try to remove it separately
		flag = q_p->remove_flag.test_and_set();
	}
	// see if either the packet is disposed or there is no packet any more
	if(flag) {
		std::unique_lock l{queue_mutex_};
		remove_queue_.push_back(ack);
		cond_.notify_one();
	}
}

std::deque<stored_packet> packet_storage::get_pending_packets(crypto::public_key_id const& receiver) {
	std::deque<stored_packet> ret;

	// get packets not yet pushed to database
	{
		std::unique_lock l{queue_mutex_};
		auto range = receiver_index_.equal_range(receiver);
		for(; range.first != range.second; ++range.first) {
			auto p = range.first->second.packet.lock();
			if(p) {
				ret.push_back(stored_packet{packet_handle{*this, p->ack, p}, p->packet});
			}
		}
	}

	auto q = db_->prepare("SELECT ack, packet FROM packets WHERE receiver = :r ORDER BY ack DESC;");
	q.bind(":r", receiver.data());
	auto res = q.execute();
	for(; res; res.next()) {
		try {
			ret.push_front(stored_packet{
				packet_handle{
					*this,
					res.value<std::int64_t>(0).value(),
					nullptr
				}, serialisation::asn_der_deserialise<transport_payload>(res.value<octet_vector>(1).value()) });
		} catch(std::exception const& ex) {
			LOG_WARN("invalid packet in database: {}", ex.what());
		}
	}

	std::sort(ret.begin(), ret.end(), [](auto const& l, auto const& r)
		{
			return l.handle.ack() < r.handle.ack();
		});

	auto last = std::unique(ret.begin(), ret.end(), [](auto const& l, auto const& r)
		{
			return l.handle.ack() == r.handle.ack();
		});

	ret.erase(last, ret.end());

	return ret;
}

bool packet_storage::next_packet(std::shared_ptr<queued_packet>& packet, ack_type& remove_ack) {
	packet = nullptr;
	remove_ack = 0;
	std::unique_lock l{queue_mutex_};
	while(!close_ && queue_.empty() && remove_queue_.empty()) {
		cond_.wait(l);
	}
	if(!queue_.empty()) {
		packet = std::move(queue_.front());
		queue_.pop_front();
		remove_from_index(packet->receiver, packet->ack);
	}
	if(!remove_queue_.empty()) {
		remove_ack = remove_queue_.front();
		remove_queue_.pop_front();
	}
	{ // some queue size statistic logging
		static int counter = 0;
		if(++counter == 1000) {
			counter = 0;
			if(queue_.size() > 1000 || remove_queue_.size() > 1000) {
				LOG_INFO("queue_.size={}, remove_queue_.size={}", queue_.size(), remove_queue_.size());
			}
		}
	}
	return !close_;
}

bool packet_storage::write_to_database(std::shared_ptr<queued_packet> const& packet) {
	static int counter = 0;
	static timer t;

	bool ret = false;
	try {
		insert_statement_->reset();
		insert_statement_->bind(":a", packet->ack);
		insert_statement_->bind(":r", packet->receiver.data());
		insert_statement_->bind(":p", serialisation::asn_der_serialise(packet->packet));
		insert_statement_->bind(":t", serialisation::clock_type::now());
		insert_statement_->execute();
		ret = true;
	} catch(std::exception const& ex) {
		LOG_WARN("failed to write to database: {}", ex.what());
	}

	if(++counter == 100) {
		counter = 0;
		LOG_TRACE("writing 100 entries to db: {} ms", t.elapsed_milliseconds());
		t.reset();
	}

	return ret;
}

void packet_storage::thread_entry() {
	std::shared_ptr<queued_packet> p;
	ack_type remove_ack{};
	while(next_packet(p, remove_ack)) {
		if(p) {
			bool write_to_db = !p->remove_flag.test_and_set();
			bool notify = true;
			if(write_to_db) {
				notify = write_to_database(p);
			}
			if(notify) {
				p->notify(p->sender, p->sender_ack);
			}
		}
		if(remove_ack) {
			remove_from_database(remove_ack);
		}
	}
}

void packet_storage::remove_from_index(crypto::public_key_id const& id, ack_type ack) {
	auto range = receiver_index_.equal_range(id);
	auto it = range.first;
	while(it != range.second && it->second.ack != ack) {
		++it;
	}
	if(it != range.second) {
		receiver_index_.erase(it);
	}
}

void packet_storage::remove_from_database(ack_type ack) {
	try {
		auto q = db_->prepare("DELETE FROM packets WHERE ack = :ack");
		q.bind(":ack", ack);
		q.execute();
	} catch(std::exception const& ex) {
		LOG_WARN("failed to remove from database: {}", ex.what());
	}
}

void packet_storage::purge_queues() {
	LOG_TRACE("purging packet storage queues (queue.size={}, remove_queue.size={})", queue_.size(), remove_queue_.size());
	for(auto&& v : queue_) {
		if(!v->remove_flag.test_and_set()) {
			write_to_database(v);
		}
	}
	queue_.clear();
	for(auto&& v : remove_queue_) {
		remove_from_database(v);
	}
	remove_queue_.clear();
}

}
