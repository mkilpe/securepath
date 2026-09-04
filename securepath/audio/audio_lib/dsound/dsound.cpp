// SPDX-License-Identifier: MIT

#include "dsound.hpp"
#include "../audio_device_modes.hpp"
#include "../util.hpp"

#include <securepath/log/log.hpp>

#include <atomic>
#include <cstring>
#include <chrono>
#include <thread>
#include <functional>

// keep windows.h from defining min/max macros that break std::min/std::max
#ifndef NOMINMAX
#	define NOMINMAX
#endif
#include <windows.h>
#include <mmsystem.h>
#include <mmreg.h>
#include <dsound.h>

#ifdef _MSC_VER
#	pragma comment( lib, "Dsound.lib" )
#	pragma comment( lib, "dxguid.lib" )
#endif

namespace securepath::audio {
namespace {

using namespace std::literals;

struct dsound_device_info : audio_device_info {
public:
	dsound_device_info(LPGUID guid, LPCWSTR desc, bool play_device)
		: audio_device_info(play_device, securepath::to_string(desc), securepath::to_string(desc))
	{
		if(guid) {
			CopyMemory(&guid_, guid, sizeof(GUID));
			has_guid_ = true;
		}
	}

	// DirectSound enumerates the primary device with a null guid; opening it
	// must pass null again, not a copy of uninitialised bytes.
	LPCGUID guid() const { return has_guid_ ? &guid_ : nullptr; }

private:
	GUID guid_{};
	bool has_guid_{};
};

// owns a COM interface pointer and releases it on destruction, so a
// constructor throw between acquisition and completion cannot leak it
template<typename T>
class com_ptr {
public:
	com_ptr() = default;
	~com_ptr() {
		if(p_) {
			p_->Release();
		}
	}
	com_ptr(com_ptr const&) = delete;
	com_ptr& operator=(com_ptr const&) = delete;

	// for COM factory out-parameters
	T** out() { return &p_; }

	T* operator->() const { return p_; }
	operator T*() const { return p_; }

private:
	T* p_{};
};

// owns the win32 event handle used for buffer position notifications
class event_handle {
public:
	event_handle()
	: h_(::CreateEventW(NULL, FALSE, FALSE, NULL))
	{
	}
	~event_handle() {
		if(h_) {
			::CloseHandle(h_);
		}
	}
	event_handle(event_handle const&) = delete;
	event_handle& operator=(event_handle const&) = delete;

	operator HANDLE() const { return h_; }
	explicit operator bool() const { return h_ != nullptr; }

private:
	HANDLE h_{};
};

// DirectSound counts buffer positions in bytes (and sizes in whole frames);
// the audio_device interface counts in interleaved samples. Convert with
// samples_to_octet_count/octets_to_sample_count at every DirectSound boundary.

// buffer position notifications are configured identically for play and
// capture buffers; both expose IDirectSoundNotify through IUnknown
void set_buffer_notifications(IUnknown& buffer, std::size_t buffer_bytes,
		std::size_t step_bytes, HANDLE event) {
	if(step_bytes == 0 || buffer_bytes % step_bytes != 0) {
		throw std::logic_error("buffer size not divisible by notification period");
	}
	std::size_t const points = buffer_bytes / step_bytes;

	com_ptr<IDirectSoundNotify> notify;
	if(buffer.QueryInterface(IID_IDirectSoundNotify, (LPVOID*)notify.out()) != DS_OK) {
		throw std::runtime_error("failed to query notification interface");
	}
	std::vector<DSBPOSITIONNOTIFY> pnot(points);
	for(std::size_t i = 0; i != points; ++i) {
		pnot[i].dwOffset = static_cast<DWORD>(step_bytes * (i+1) - 1);
		pnot[i].hEventNotify = event;
	}
	if(notify->SetNotificationPositions(static_cast<DWORD>(pnot.size()), pnot.data()) != DS_OK) {
		throw std::runtime_error("failed to set notification positions");
	}
}

using enum_calltype = std::function<void (LPGUID, LPCWSTR)>;

BOOL CALLBACK enumerate_devices(LPGUID lpGuid, LPCWSTR lpszDesc, LPCWSTR lpszModule, LPVOID context) {
	(*static_cast<enum_calltype*>(context))(lpGuid, lpszDesc);
	return TRUE;
}

}

class dsound_play_device : public audio_play_device {
public:
	dsound_play_device(LPCGUID guid, device_config config)
		: config_(config)
	{
		if(!not_handle_) {
			throw std::runtime_error("failed to create notification handle");
		}
		if(::DirectSoundCreate8(guid, device_.out(), 0) != DS_OK) {
			throw std::runtime_error("failed to create device");
		}
		if(device_->SetCooperativeLevel(::GetDesktopWindow(), DSSCL_NORMAL) != DS_OK) {
			throw std::runtime_error("failed to set cooperative level");
		}
		std::memset(&format_, 0, sizeof(format_));
		format_.wFormatTag = (config_.format.type == sample_type::float_t) ? WAVE_FORMAT_IEEE_FLOAT : WAVE_FORMAT_PCM;
		format_.nChannels = config_.format.channels;
		format_.wBitsPerSample = config_.format.bits_per_sample;
		format_.nSamplesPerSec = config_.format.samples_per_second;
		format_.nBlockAlign = format_.nChannels * format_.wBitsPerSample / 8;
		format_.nAvgBytesPerSec = format_.nBlockAlign * format_.nSamplesPerSec;

		DSBUFFERDESC desc = {0};
		desc.dwSize = sizeof( DSBUFFERDESC );
		desc.dwFlags = DSBCAPS_GLOBALFOCUS | DSBCAPS_CTRLVOLUME
			| DSBCAPS_CTRLPOSITIONNOTIFY | DSBCAPS_GETCURRENTPOSITION2;
		// buffer_size is in samples; size the ring in whole frames and report
		// the rounded size back through config(), like the ALSA backend
		desc.dwBufferBytes = static_cast<DWORD>(
			config_.buffer_size / format_.nChannels * format_.nBlockAlign);
		desc.lpwfxFormat = &format_;

		HRESULT res = device_->CreateSoundBuffer(&desc, buffer_.out(), 0);
		if( res != DS_OK ) {
			LOG_TRACE("failed to create play buffer: {:#x}", static_cast<std::uint32_t>(res));
			throw std::runtime_error("failed to create play buffer");
		}
		buffer_size_in_bytes_ = desc.dwBufferBytes;
		config_.buffer_size = octets_to_sample_count(config_.format, buffer_size_in_bytes_);

		//initialise to zeros
		void* p = 0;
		DWORD s = 0;
		HRESULT h = buffer_->Lock(0, buffer_size_in_bytes_, &p, &s, 0, 0, 0);
		if( h != DS_OK || s != buffer_size_in_bytes_ ) {
			throw std::runtime_error("failed to create play buffer");
		}
		std::memset( p, 0, s );
		buffer_->Unlock(p, s, 0, 0);
	}

	~dsound_play_device() {
		if(buffer_) {
			buffer_->Stop();
		}
	}

	void start() {
		HRESULT h = buffer_->Play(0, 0, DSBPLAY_LOOPING);
		if( h != DS_OK ) {
			LOG_TRACE("buffer play failed: {:#x}", static_cast<std::uint32_t>(h));
			throw std::runtime_error("buffer play failed");
		}
		running_ = true;
	}

	void stop(stop_type s) {
		if(s == stop_type::drain && running_) {
			drain();
		}
		running_ = false;
		buffer_->Stop();
		// wake a wait() parked on the notification event
		::SetEvent(not_handle_);
	}

	virtual std::size_t buffer_size() const {
		return config_.buffer_size;
	}

	virtual bool wait() {
		// finite timeout so a wedged device cannot park the caller forever;
		// stop() signals the event to interrupt an in-progress wait
		return ::WaitForSingleObject(not_handle_, 1000) == WAIT_OBJECT_0 && running_;
	}

	virtual int supported_modes() const {
		return audio_device_mode::notifications;
	}

	// Must be called while the buffer is stopped (the player configures the
	// mode right after creating the device).
	void set_notification(std::size_t samples) {
		set_buffer_notifications(*buffer_, buffer_size_in_bytes_,
			samples_to_octet_count(config_.format, samples), not_handle_);
	}

	virtual void set_mode(mode const& m) {
		if(notification_mode const* p = dynamic_cast<notification_mode const*>(&m)) {
			set_notification(p->samples);
		}
	}

	virtual device_config config() const {
		return config_;
	}

	virtual std::size_t avail() const {
		DWORD play_pos;
		DWORD write_pos;
		HRESULT h = buffer_->GetCurrentPosition(&play_pos, &write_pos);
		if( h != DS_OK ) {
			LOG_TRACE("error: {}", ::GetLastError());
			throw std::runtime_error("buffer get current position failed");
		}
		int size = play_pos - pos_;
		if( size < 0 ) {
			size += buffer_size_in_bytes_;
		}
		// keep one frame unwritten so pos_ == play cursor always means "all
		// played", never "exactly full": drain() relies on the distinction
		size = std::max(size - int(format_.nBlockAlign), 0);
		return octets_to_sample_count(config_.format, size);
	}

	std::size_t write_to_buffer(uint8_t const* buf, std::size_t size) {
		void* p1 = 0;
		void* p2 = 0;
		DWORD s1 = 0, s2 = 0;

		HRESULT h = buffer_->Lock(pos_, size, &p1, &s1, &p2, &s2, 0);

		if( h == DS_OK ) {
			if( s1 ) {
				std::memcpy(p1, buf, s1);
				if( s2 ) {
					std::memcpy(p2, buf+s1, s2);
				}
			}
			buffer_->Unlock(p1, s1, p2, s2);
			pos_ += s1+s2;
			pos_ %= buffer_size_in_bytes_;
		}
		return s1+s2;
	}

	virtual std::size_t write(audio_buffer& b) {
		std::size_t size = samples_to_octet_count(config_.format, avail());
		if( pos_ == 0 && !running_ ) {
			// pre-start fill: same one-frame reservation as avail()
			size = std::min<std::size_t>(b.used_size(), buffer_size_in_bytes_ - format_.nBlockAlign);
		}
		std::size_t consumed = 0;
		if( size ) {
			consumed = write_to_buffer(b.begin<uint8_t>(), std::min<std::size_t>( size, b.used_size() ));
			b.consume(consumed);
		}
		return octets_to_sample_count(config_.format, consumed);
	}

private:
	// Wait until the play cursor has consumed everything written so far. The
	// write cursor from GetCurrentPosition cannot be used here: DirectSound
	// keeps it a fixed lead ahead of the play cursor, so the two never meet
	// while the buffer runs. Sleep out the distance to our own write position
	// (pos_) instead, silencing the stale region past it first. remaining == 0
	// unambiguously means "all played": writes reserve one frame, so pos_ can
	// never wrap onto the play cursor from behind.
	void drain() {
		DWORD play_pos = 0;
		DWORD write_pos = 0;
		if(buffer_->GetCurrentPosition(&play_pos, &write_pos) == DS_OK) {
			DWORD const remaining = (pos_ + buffer_size_in_bytes_ - play_pos) % buffer_size_in_bytes_;
			zero_buffer_region(pos_, buffer_size_in_bytes_ - remaining);
			std::this_thread::sleep_for(
				std::chrono::milliseconds(remaining * 1000ull / format_.nAvgBytesPerSec));
		}
	}

	void zero_buffer_region(DWORD start, DWORD length) {
		if(length) {
			void* p1 = 0;
			void* p2 = 0;
			DWORD s1 = 0, s2 = 0;
			if(buffer_->Lock(start, length, &p1, &s1, &p2, &s2, 0) == DS_OK) {
				if(s1) {
					std::memset(p1, 0, s1);
				}
				if(s2) {
					std::memset(p2, 0, s2);
				}
				buffer_->Unlock(p1, s1, p2, s2);
			}
		}
	}

private:
	device_config config_;
	std::atomic<bool> running_{};
	std::size_t buffer_size_in_bytes_{};
	DWORD pos_{};
	event_handle not_handle_;

	com_ptr<IDirectSound8> device_;
	com_ptr<IDirectSoundBuffer> buffer_;
	WAVEFORMATEX format_{};
};

class dsound_capture_device : public audio_capture_device  {
public:
	dsound_capture_device(LPCGUID guid, device_config config)
		: config_(config)
	{
		if(!not_handle_) {
			throw std::runtime_error("failed to create notification handle");
		}
		HRESULT device_res = ::DirectSoundCaptureCreate8(guid, device_.out(), 0);
		if(device_res != DS_OK) {
			LOG_TRACE("failed to create capture device: {:#x}", static_cast<std::uint32_t>(device_res));
			throw std::runtime_error("failed to create device");
		}

		std::memset(&format_, 0, sizeof(format_));
		format_.wFormatTag = WAVE_FORMAT_PCM;
		format_.nChannels = config_.format.channels;
		format_.wBitsPerSample = config_.format.bits_per_sample;
		format_.nSamplesPerSec = config_.format.samples_per_second;
		format_.nBlockAlign = format_.nChannels * format_.wBitsPerSample / 8;
		format_.nAvgBytesPerSec = format_.nBlockAlign * format_.nSamplesPerSec;

		DSCBUFFERDESC desc = {0};
		desc.dwSize = sizeof(DSCBUFFERDESC);
		desc.dwFlags = DSCBCAPS_WAVEMAPPED;
		// buffer_size is in samples; size the ring in whole frames and report
		// the rounded size back through config(), like the ALSA backend
		desc.dwBufferBytes = static_cast<DWORD>(
			config_.buffer_size / format_.nChannels * format_.nBlockAlign);
		desc.lpwfxFormat = &format_;

		HRESULT res = device_->CreateCaptureBuffer(&desc, buffer_.out(), 0);
		if(res != DS_OK) {
			LOG_TRACE("failed to create capture buffer: {:#x}", static_cast<std::uint32_t>(res));
			throw std::runtime_error("failed to create capture buffer");
		}

		buffer_size_in_bytes_ = desc.dwBufferBytes;
		config_.buffer_size = octets_to_sample_count(config_.format, buffer_size_in_bytes_);
	}

	~dsound_capture_device() {
		if(buffer_) {
			buffer_->Stop();
		}
	}

	void start() {
		buffer_->Start(DSCBSTART_LOOPING);
	}

	void stop(stop_type s) {
		if(s == stop_type::drain) {
			// bounded: give the device one buffer's worth of time to make the
			// remaining captured data readable, then stop regardless
			auto const deadline = std::chrono::steady_clock::now()
				+ std::chrono::milliseconds(1000ull * buffer_size_in_bytes_ / format_.nAvgBytesPerSec)
				+ 100ms;
			DWORD capture_pos = 0;
			DWORD read_pos = 0;
			bool pending = true;
			while(pending && std::chrono::steady_clock::now() < deadline) {
				pending = buffer_->GetCurrentPosition(&capture_pos, &read_pos) == DS_OK
					&& capture_pos != read_pos;
				if(pending) {
					std::this_thread::sleep_for(10ms);
				}
			}
		}
		buffer_->Stop();
		SetEvent(not_handle_);
	}

	virtual std::size_t buffer_size() const {
		return config_.buffer_size;
	}
	
	virtual device_config config() const {
		return config_;
	}

	virtual std::size_t avail() const {
		DWORD capture_pos;
		DWORD read_pos;
		HRESULT h = buffer_->GetCurrentPosition(&capture_pos, &read_pos);
		if(h != DS_OK) {
			LOG_TRACE("error: {}", ::GetLastError());
			throw std::runtime_error("buffer get current position failed");
		}
		int size = read_pos - pos_;
		if(size < 0) {
			size += buffer_size_in_bytes_;
		}
		return octets_to_sample_count(config_.format, size);
	}

	void set_notification(std::size_t samples) {
		set_buffer_notifications(*buffer_, buffer_size_in_bytes_,
			samples_to_octet_count(config_.format, samples), not_handle_);
	}

	std::size_t capture_to_buffer(uint8_t* buf, std::size_t size) {
		void* p1 = 0;
		void* p2 = 0;
		DWORD s1 = 0, s2 = 0;
		HRESULT h = buffer_->Lock(pos_, size, &p1, &s1, &p2, &s2, 0);
		if( h == DS_OK ) {
			if( s1 ) {
				std::memcpy(buf, p1, s1);
				if( s2 ) {
					std::memcpy(buf+s1, p2, s2);
				}
			}
			buffer_->Unlock(p1, s1, p2, s2);
			pos_ += s1 + s2;
			pos_ %= buffer_size_in_bytes_;
		}
		return s1+s2;
	}

	virtual std::size_t read(audio_buffer& b) {
		std::size_t read_size = 0;
		std::size_t size = samples_to_octet_count(config_.format, avail());
		if(size) {
			read_size = capture_to_buffer(b.free_begin<uint8_t>(), std::min<std::size_t>( size, b.free_size() ));
			b.conserve(read_size);
		}
		return octets_to_sample_count(config_.format, read_size);
	}

	virtual int supported_modes() const {
		return audio_device_mode::notifications;
	}

	virtual void set_mode(mode const& m) {
		if(notification_mode const* p = dynamic_cast<notification_mode const*>(&m)) {
			set_notification(p->samples);
		}
	}

	bool wait() {
		::WaitForSingleObject(not_handle_, INFINITE);
		return true;
	}

private:
	device_config config_;
	std::size_t buffer_size_in_bytes_{};

	DWORD pos_{};
	event_handle not_handle_;

	com_ptr<IDirectSoundCapture8> device_;
	com_ptr<IDirectSoundCaptureBuffer> buffer_;
	WAVEFORMATEX format_{};
};

std::string dsound_audio_interface::name() const {
	return "DirectSound";
}

adinfos dsound_audio_interface::enumerate_devices(audio_device_type type) const {
	adinfos devices;
	if( type & audio_device_t::play ) {
		enum_calltype callback = [&](LPGUID guid, LPCWSTR desc) {
			devices.push_back(std::make_shared<dsound_device_info>(guid, desc, true));
		};
		if(FAILED(::DirectSoundEnumerateW(&audio::enumerate_devices, &callback))) {
			throw std::runtime_error("failed to enumerate audio devices");
		}
	}
	if( type & audio_device_t::capture ) {
		enum_calltype callback = [&](LPGUID guid, LPCWSTR desc) {
			devices.push_back(std::make_shared<dsound_device_info>(guid, desc, false));
		};
		if(FAILED(::DirectSoundCaptureEnumerateW(&audio::enumerate_devices, &callback))) {
			throw std::runtime_error("failed to enumerate audio devices");
		}
	}
	return devices;
}

audio_play_device_ptr dsound_audio_interface::play_device(device_config const& config, audio_device_info_ptr info) const {
	dsound_device_info* p = info ? dynamic_cast<dsound_device_info*>(info.get()) : nullptr;
	if(info && (!p || !info->is_play_device())) {
		throw std::runtime_error("invalid audio play device info");
	}
	return audio_play_device_ptr(new dsound_play_device(p ? p->guid() : nullptr, config));
}

audio_capture_device_ptr dsound_audio_interface::capture_device(device_config const& config, audio_device_info_ptr info) const {
	dsound_device_info* p = info ? dynamic_cast<dsound_device_info*>(info.get()) : nullptr;
	if(info && (!p || info->is_play_device())) {
		throw std::runtime_error("invalid audio capture device info");
	}
	return audio_capture_device_ptr(new dsound_capture_device(p ? p->guid() : nullptr, config));
}

}
