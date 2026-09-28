/*
 * Dacar C++ port — two-process rfed publish interop test (Resource path).
 *
 * Spawns the resource_sink executable (a second Reticulum stack in its own
 * process acting as a minimal rfed publish node), connects over a
 * point-to-point UDP interface, and drives RFedClient::send_publish through
 * both wire paths the node model accepts:
 *
 *   - the DATA path: a small (single-packet) publish arrives on the sink's
 *     publish destination as a plain packet;
 *   - the Resource path: an oversized (> 431-byte) publish is advertised as
 *     a Resource over an accepted link; the sink's ACCEPT_ALL ingestion
 *     records the assembled transfer.
 *
 * The test asserts the transport results (DATA accepted, Resource COMPLETE)
 * and verifies the sink received both payloads byte-exactly (SHA-256 in the
 * sink's report file). Exercises the real transport path end to end — the
 * single-process loopback can't deliver data packets (Transport's
 * packet-hash dedup filters looped-back traffic).
 *
 * Exit code 0 = both publish paths behaved exactly as specified.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "UdpPointInterface.h"

#include "rfed/Client.h"
#include "rfed/Constants.h"

#include <microStore/Adapters/UniversalFileSystem.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

#include <signal.h>

#ifndef SINK_EXECUTABLE
#define SINK_EXECUTABLE "./resource_sink"
#endif

static RNS::Bytes fillBytes(size_t size, uint8_t fill) {
	RNS::Bytes out;
	memset(out.writable(size), fill, size);
	return out;
}

static bool waitForReportLine(const std::string& reportFile, const std::string& needle,
	RNS::Reticulum& reticulum, double timeoutSeconds) {
	const double deadline = RNS::Utilities::OS::time() + timeoutSeconds;
	while (RNS::Utilities::OS::time() < deadline) {
		reticulum.loop(); // keep pumping while we wait
		FILE* fh = fopen(reportFile.c_str(), "r");
		if (fh != nullptr) {
			char line[256];
			while (fgets(line, sizeof(line), fh) != nullptr) {
				if (strstr(line, needle.c_str()) != nullptr) {
					fclose(fh);
					return true;
				}
			}
			fclose(fh);
		}
		RNS::Utilities::OS::sleep(0.05);
	}
	return false;
}

int main() {
	// Scratch CWD (microStore's PosixFileSystem is CWD-relative on native).
	char tmpl[] = "/tmp/dacar-rfed-client-XXXXXX";
	char* dir = mkdtemp(tmpl);
	if (!dir) {
		fprintf(stderr, "mkdtemp failed\n");
		return 1;
	}
	if (chdir(dir) != 0) {
		fprintf(stderr, "chdir failed\n");
		return 1;
	}

	// Point-to-point ports, derived from the PID to avoid collisions.
	const int clientPort = 46000 + (getpid() % 10000);
	const int sinkPort = clientPort + 1;
	const std::string peerFile = std::string(dir) + "/sink.peer";
	const std::string reportFile = std::string(dir) + "/sink.report";

	// -- spawn the sink in a second process (second RNS stack) --------------
	const std::string sinkLog = std::string(dir) + "/sink.log";
	const std::string sinkPortArg = std::to_string(sinkPort);
	const std::string clientPortArg = std::to_string(clientPort);
	const pid_t sinkPid = fork();
	if (sinkPid == 0) {
		freopen(sinkLog.c_str(), "w", stdout);
		freopen(sinkLog.c_str(), "w", stderr);
		execl(SINK_EXECUTABLE, SINK_EXECUTABLE,
			sinkPortArg.c_str(), clientPortArg.c_str(),
			peerFile.c_str(), reportFile.c_str(), (char*)nullptr);
		_exit(127);
	}
	if (sinkPid < 0) {
		fprintf(stderr, "failed to spawn sink\n");
		return 1;
	}

	int failures = 0;
	try {
		// -- client stack ---------------------------------------------------
		static microStore::Adapters::UniversalFileSystem filesystem;
		RNS::Utilities::OS::register_filesystem(filesystem);

		static UdpPointInterface* udp = new UdpPointInterface("client-udp", clientPort, "127.0.0.1", sinkPort);
		if (!udp->start()) {
			fprintf(stderr, "FAIL: failed to bind UDP port %d\n", clientPort);
			kill(sinkPid, SIGTERM);
			return 1;
		}
		RNS::Interface udp_handle(udp);
		RNS::Transport::register_interface(udp_handle);

		RNS::Reticulum reticulum = RNS::Reticulum();
		reticulum.transport_enabled(true);
		reticulum.start();

		// -- wait for the sink's discovery file ------------------------------
		std::string destHex;
		const double fileDeadline = RNS::Utilities::OS::time() + 15.0;
		while (RNS::Utilities::OS::time() < fileDeadline) {
			reticulum.loop();
			FILE* fh = fopen(peerFile.c_str(), "r");
			if (fh != nullptr) {
				char hashBuf[64] = {0};
				char pubBuf[128] = {0};
				if (fscanf(fh, "%63s %127s", hashBuf, pubBuf) == 2) {
					destHex = hashBuf;
				}
				fclose(fh);
				if (!destHex.empty()) break;
			}
			RNS::Utilities::OS::sleep(0.05);
		}
		if (destHex.empty()) {
			fprintf(stderr, "FAIL: sink never published its discovery file\n");
			kill(sinkPid, SIGTERM);
			return 1;
		}

		// -- client + publish target -----------------------------------------
		RNS::Identity clientIdentity(true);
		RFed::RFedClient client(clientIdentity, reticulum);

		const RNS::Bytes nodeHash = [&destHex]() {
			RNS::Bytes out;
			out.assignHex(destHex.c_str());
			return out;
		}();

		// -- DATA path: a single-packet publish -------------------------------
		const RNS::Bytes small = fillBytes(RFed::PUBLISH_DATA_PACKET_MAX, 0xA5);
		const RNS::Bytes smallDigest = RNS::Cryptography::sha256(small);
		if (!client.send_publish(nodeHash, small)) {
			fprintf(stderr, "FAIL: DATA-path publish was not accepted by the transport\n");
			failures++;
		}
		else if (!waitForReportLine(reportFile,
				"DATA 0 " + std::to_string(small.size()) + " " + smallDigest.toHex(),
				reticulum, 15.0)) {
			fprintf(stderr, "FAIL: DATA publish never arrived at the sink (or bytes differ)\n");
			failures++;
		}
		else {
			printf("PASS: DATA-path publish (%zu bytes) arrived intact\n", small.size());
		}

		// -- Resource path: an oversized publish ------------------------------
		const size_t bigSize = RFed::PUBLISH_DATA_MAX * 4;
		const RNS::Bytes big = fillBytes(bigSize, 0x5A);
		const RNS::Bytes bigDigest = RNS::Cryptography::sha256(big);
		if (!client.send_publish(nodeHash, big)) {
			fprintf(stderr, "FAIL: Resource-path publish did not conclude COMPLETE\n");
			failures++;
		}
		else if (!waitForReportLine(reportFile,
				"RESOURCE " + std::to_string(RNS::Type::Resource::COMPLETE) + " " +
					std::to_string(bigSize) + " " + bigDigest.toHex(),
				reticulum, 15.0)) {
			fprintf(stderr, "FAIL: Resource publish never arrived at the sink (or bytes differ)\n");
			failures++;
		}
		else {
			printf("PASS: Resource-path publish (%zu bytes) transferred intact\n", bigSize);
		}
	}
	catch (const std::exception& e) {
		fprintf(stderr, "FAIL: exception: %s\n", e.what());
		failures++;
	}

	kill(sinkPid, SIGTERM);

	// Surface the sink log on failure for post-mortem.
	if (failures > 0) {
		FILE* fh = fopen(sinkLog.c_str(), "r");
		if (fh != nullptr) {
			char buf[1024];
			size_t n;
			fprintf(stderr, "--- sink log ---\n");
			while ((n = fread(buf, 1, sizeof(buf), fh)) > 0) {
				fwrite(buf, 1, n, stderr);
			}
			fclose(fh);
		}
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("rfed publish interop: all paths OK\n");
	return 0;
}
