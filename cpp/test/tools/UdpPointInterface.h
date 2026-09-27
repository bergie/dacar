/*
 * Dacar C++ port — minimal native UDP interface for the §8 interop tests.
 *
 * A trimmed, native-only variant of microReticulum's
 * examples/common/udp_interface UDPInterface: point-to-point datagram transport
 * between two Reticulum instances on one host (or across a network), with
 * runtime-configurable ports (the example binds via compile-time macros).
 *
 * Packets are read in loop() — pumped by Reticulum::loop() like every
 * interface — and sent as datagrams to the configured peer.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include <microReticulum/Interface.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

class UdpPointInterface : public RNS::InterfaceImpl {

public:
	static const uint32_t BITRATE_GUESS = 10 * 1000 * 1000;

	UdpPointInterface(
		const char* name,
		int local_port,
		const char* remote_host,
		int remote_port
	) : RNS::InterfaceImpl(name),
		_local_port(local_port),
		_remote_host(remote_host),
		_remote_port(remote_port)
	{
		_OUT = true;
		_IN = true;
		_mode = RNS::Type::Interface::MODE_FULL;
		// Declare the interface's hardware MTU. With HW_MTU left at 0 the
		// receiving-side LINKREQUEST MTU clamp strips the signalling bytes
		// from packet.data(), which changes the responder's link id
		// derivation relative to the initiator and breaks proof matching.
		_HW_MTU = 1500;
	}

	virtual ~UdpPointInterface() {
		stop();
		_name = "(deleted)";
	}

	bool start() {
		_socket = ::socket(AF_INET, SOCK_DGRAM, 0);
		if (_socket < 0) {
			return false;
		}
		struct sockaddr_in local;
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		local.sin_port = htons((uint16_t)_local_port);
		if (::bind(_socket, (struct sockaddr*)&local, sizeof(local)) < 0) {
			::close(_socket);
			_socket = -1;
			return false;
		}
		memset(&_remote, 0, sizeof(_remote));
		_remote.sin_family = AF_INET;
		_remote.sin_addr.s_addr = inet_addr(_remote_host.c_str());
		_remote.sin_port = htons((uint16_t)_remote_port);
		return true;
	}

	void stop() {
		if (_socket >= 0) {
			::close(_socket);
			_socket = -1;
		}
	}

	virtual void loop() {
		if (_socket < 0) {
			return;
		}
		std::vector<uint8_t> buffer(65536);
		while (true) {
			ssize_t received = ::recv(_socket, buffer.data(), buffer.size(), MSG_DONTWAIT);
			if (received <= 0) {
				break;
			}
			handle_incoming(RNS::Bytes(buffer.data(), (size_t)received));
		}
	}

	virtual inline std::string toString() const {
		return "UdpPointInterface[" + std::to_string(_local_port) + "->" + _remote_host + ":" + std::to_string(_remote_port) + "]";
	}

protected:
	virtual bool send_outgoing(const RNS::Bytes& data) {
		if (_socket < 0 || !data) {
			return false;
		}
		ssize_t sent = ::sendto(
			_socket, data.data(), data.size(), 0,
			(struct sockaddr*)&_remote, sizeof(_remote)
		);
		InterfaceImpl::handle_outgoing(data);
		return sent == (ssize_t)data.size();
	}

private:
	int _socket = -1;
	int _local_port;
	std::string _remote_host;
	int _remote_port;
	struct sockaddr_in _remote;
};
