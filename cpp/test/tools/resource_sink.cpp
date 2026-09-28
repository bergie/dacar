/*
 * Dacar C++ port — rfed publish sink for the two-process Resource interop
 * test.
 *
 * A standalone minimal rfed publish endpoint: runs the `rfed.channel.publish`
 * destination over a point-to-point UDP interface and ingests both wire paths
 * a rfed node accepts —
 *
 *   - fire-and-forget DATA packets (single-packet publishes), and
 *   - Resources advertised over an accepted link (oversized publishes),
 *
 * recording every arrival as a line in the report file:
 *
 *     DATA <size> <sha256-hex>
 *     RESOURCE <status> <size> <sha256-hex>
 *
 * usage: resource_sink <listen_port> <remote_port> <peer_file> <report_file>
 *
 * Writes "<dest_hash_hex> <pub_hex>" to <peer_file> once announced (the
 * client's discovery cue) and runs until killed.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "UdpPointInterface.h"

#include <microStore/Adapters/UniversalFileSystem.h>

#include "microReticulum/Cryptography/Hashes.h"
#include "microReticulum/Destination.h"
#include "microReticulum/Log.h"
#include "microReticulum/Resource.h"
#include "microReticulum/Reticulum.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <signal.h>
#include <unistd.h>

static volatile bool _running = true;

static void on_signal(int) {
	_running = false;
}

static const char* _reportFile = "";

static void report(const char* kind, unsigned long status, size_t size, const RNS::Bytes& data) {
	const RNS::Bytes digest = RNS::Cryptography::sha256(data);
	FILE* fh = fopen(_reportFile, "a");
	if (fh != nullptr) {
		fprintf(fh, "%s %lu %zu %s\n", kind, status, size, digest.toHex().c_str());
		fclose(fh);
	}
}

int main(int argc, char** argv) {
	if (argc < 5) {
		fprintf(stderr,
			"usage: %s <listen_port> <remote_port> <peer_file> <report_file>\n", argv[0]);
		return 2;
	}
	const int listenPort = atoi(argv[1]);
	const int remotePort = atoi(argv[2]);
	const char* peerFile = argv[3];
	_reportFile = argv[4];

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	char tmpl[] = "/tmp/dacar-rfed-sink-XXXXXX";
	char* dir = mkdtemp(tmpl);
	if (!dir) {
		fprintf(stderr, "mkdtemp failed\n");
		return 1;
	}
	if (chdir(dir) != 0) {
		fprintf(stderr, "chdir failed\n");
		return 1;
	}

	try {
		static microStore::Adapters::UniversalFileSystem filesystem;
		RNS::Utilities::OS::register_filesystem(filesystem);

		static UdpPointInterface* udp = new UdpPointInterface("sink-udp", listenPort, "127.0.0.1", remotePort);
		if (!udp->start()) {
			fprintf(stderr, "failed to bind UDP port %d\n", listenPort);
			return 1;
		}
		RNS::Interface udp_handle(udp);
		RNS::Transport::register_interface(udp_handle);

		RNS::Reticulum reticulum = RNS::Reticulum();
		reticulum.transport_enabled(true);
		reticulum.start();

		RNS::Identity identity(true);
		RNS::Destination publish(identity, RNS::Type::Destination::IN,
			RNS::Type::Destination::SINGLE, "rfed", "channel.publish");
		publish.accepts_links(true);

		// Fire-and-forget DATA path: plain packets on the publish destination.
		publish.set_packet_callback([](const RNS::Bytes& data, const RNS::Packet& packet) {
			(void)packet;
			report("DATA", 0, data.size(), data);
		});

		// Resource path: accept every advertised resource on an accepted
		// link and record its arrival (mirrors a rfed node's ACCEPT_ALL
		// ingestion of oversized publishes).
		publish.set_link_established_callback([](RNS::Link& link) {
			link.set_resource_strategy(RNS::Type::Link::ACCEPT_ALL);
			link.set_resource_concluded_callback([](const RNS::Resource& resource) {
				report("RESOURCE", (unsigned long)resource.status(), resource.data().size(), resource.data());
			});
		});

		printf("sink destination: %s\n", publish.hash().toHex().c_str());

		// Announce until killed; publish the discovery file once announced.
		for (int i = 0; i < 50 && _running; i++) {
			publish.announce();
			const double deadline = RNS::Utilities::OS::time() + 0.2;
			while (RNS::Utilities::OS::time() < deadline && _running) {
				reticulum.loop();
				RNS::Utilities::OS::sleep(0.02);
			}
			FILE* fh = fopen(peerFile, "w");
			if (fh != nullptr) {
				fprintf(fh, "%s %s\n",
					publish.hash().toHex().c_str(),
					identity.get_public_key().toHex().c_str());
				fclose(fh);
				break;
			}
		}
		printf("sink ready\n");
		fflush(stdout);

		while (_running) {
			reticulum.loop();
			RNS::Utilities::OS::sleep(0.02);
		}

		printf("sink exiting\n");
		return 0;
	}
	catch (const std::exception& e) {
		fprintf(stderr, "sink exception: %s\n", e.what());
		return 1;
	}
}
