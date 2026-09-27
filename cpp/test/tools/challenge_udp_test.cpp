/*
 * Dacar C++ port — two-process §8 challenge interop over UDP loopback.
 *
 * Spawns the standalone challenge_authority executable (a second Reticulum
 * stack in its own process), connects over a point-to-point UDP interface,
 * and runs the full §8 flow: announce discovery, Link establishment, hashed
 * challenge, signed Freshness Receipt verification. Exercises the real
 * transport path end to end — the single-process loopback can't deliver
 * data packets (Transport's packet-hash dedup filters looped-back traffic).
 *
 * Verdicts verified:
 *   - bob holds buzzer:sound at the authority        -> ALLOW  (buzz)
 *   - alice's grant exists only in the client state  -> signed DENY (no buzz)
 *
 * Exit code 0 = the §8 flow behaved exactly as specified.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Dacar.h"
#include "Dacar/RnsChallenge.h"
#include "UdpPointInterface.h"

using namespace Dacar;

#include <microStore/Adapters/UniversalFileSystem.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/wait.h>
#include <unistd.h>

#include <signal.h>

#ifndef AUTHORITY_EXECUTABLE
#define AUTHORITY_EXECUTABLE "./challenge_authority"
#endif

static const char* FIXTURE_SALT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

static RNS::Bytes hashFromByte(uint8_t fill) {
	RNS::Bytes out;
	memset(out.writable(16), fill, 16);
	return out;
}

static RNS::Bytes fillBytes(size_t size, uint8_t fill) {
	RNS::Bytes out;
	memset(out.writable(size), fill, size);
	return out;
}

int main() {
	// Scratch CWD (microStore's PosixFileSystem is CWD-relative on native).
	char tmpl[] = "/tmp/dacar-challenge-client-XXXXXX";
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
	const int clientPort = 40000 + (getpid() % 10000);
	const int authorityPort = clientPort + 1;
	const std::string peerFile = std::string(dir) + "/authority.peer";
	const std::string clientDir = dir;

	// -- spawn the authority in a second process (second RNS stack) --------
	// Its output goes to a log file (surfaced on failure); it is stopped
	// explicitly at the end — pclose/waiting on it would block forever.
	const std::string authLog = std::string(dir) + "/authority.log";
	const std::string authorityPortArg = std::to_string(authorityPort);
	const std::string clientPortArg = std::to_string(clientPort);
	const pid_t authorityPid = fork();
	if (authorityPid == 0) {
		freopen(authLog.c_str(), "w", stdout);
		freopen(authLog.c_str(), "w", stderr);
		execl(AUTHORITY_EXECUTABLE, AUTHORITY_EXECUTABLE,
			authorityPortArg.c_str(), clientPortArg.c_str(),
			peerFile.c_str(), FIXTURE_SALT_HEX, (char*)nullptr);
		_exit(127);
	}
	if (authorityPid < 0) {
		fprintf(stderr, "failed to spawn authority\n");
		return 1;
	}

	int failures = 0;
	int rc = 1;
	try {
		// -- client stack -------------------------------------------------
		static microStore::Adapters::UniversalFileSystem filesystem;
		RNS::Utilities::OS::register_filesystem(filesystem);

		static UdpPointInterface* udp = new UdpPointInterface("client-udp", clientPort, "127.0.0.1", authorityPort);
		if (!udp->start()) {
			fprintf(stderr, "FAIL: failed to bind UDP port %d\n", clientPort);
			kill(authorityPid, SIGTERM);
			return 1;
		}
		RNS::Interface udp_handle(udp);
		RNS::Transport::register_interface(udp_handle);

		RNS::Reticulum reticulum = RNS::Reticulum();
		reticulum.transport_enabled(true);
		reticulum.start();

		// -- wait for the authority's discovery file ----------------------
		std::string destHex;
		std::string pubHex;
		const double fileDeadline = RNS::Utilities::OS::time() + 15.0;
		while (RNS::Utilities::OS::time() < fileDeadline) {
			reticulum.loop();
			FILE* fh = fopen(peerFile.c_str(), "r");
			if (fh != nullptr) {
				char hashBuf[64] = {0};
				char pubBuf[128] = {0};
				const int got = fscanf(fh, "%63s %127s", hashBuf, pubBuf);
				fclose(fh);
				if (got == 2) {
					destHex = hashBuf;
					pubHex = pubBuf;
					break;
				}
			}
			RNS::Utilities::OS::sleep(0.05);
		}
		if (destHex.empty()) {
			fprintf(stderr, "FAIL: authority never published its discovery file\n");
			kill(authorityPid, SIGTERM);
			return 1;
		}
		printf("authority at %s (pub %s)\n", destHex.c_str(), pubHex.c_str());

		RNS::Bytes server_dest_hash;
		server_dest_hash.assignHex(destHex.c_str());
		const RNS::Bytes authoritativePub = [&pubHex]() {
			RNS::Bytes out;
			out.assignHex(pubHex.c_str());
			return out;
		}();

		// -- path discovery (pump until the announce lands) -----------------
		bool hasPath = false;
		const double pathDeadline = RNS::Utilities::OS::time() + 15.0;
		while (RNS::Utilities::OS::time() < pathDeadline) {
			reticulum.loop();
			if (RNS::Transport::has_path(server_dest_hash)) {
				hasPath = true;
				break;
			}
			RNS::Utilities::OS::sleep(0.05);
		}
		if (!hasPath) {
			fprintf(stderr, "FAIL: no path to the authority destination\n");
			kill(authorityPid, SIGTERM);
			return 1;
		}

		const RNS::Identity recalled = RNS::Identity::recall(server_dest_hash);
		if (!recalled) {
			fprintf(stderr, "FAIL: could not recall the authority identity\n");
			kill(authorityPid, SIGTERM);
			return 1;
		}
		const RNS::Destination remote(recalled, RNS::Type::Destination::OUT, RNS::Type::Destination::SINGLE, APP_NAME, DACAR_CHALLENGE_ASPECTS);

		RNS::Link link = establish_challenge_link(reticulum, remote, 15.0);
		if (!link || link.status() != RNS::Type::Link::ACTIVE) {
			fprintf(stderr, "FAIL: link did not establish\n");
			kill(authorityPid, SIGTERM);
			return 1;
		}
		printf("link established\n");

		// -- client-side config/state ---------------------------------------
		RNS::Bytes salt;
		salt.assignHex(FIXTURE_SALT_HEX);
		Dacar::Set<RNS::Bytes> anchors{server_dest_hash};
		Dacar::Config config(anchors, salt, {}, {}, server_dest_hash);

		// Divergent state: alice's grant exists only locally (in flight).
		Dacar::StateVector state(config.deletion_horizon_days());
		const uint64_t stamp = 0x0000123456780000ULL;
		for (const RNS::Bytes& grantee : {hashFromByte(0x03), hashFromByte(0x04)}) {
			Dacar::Tuple grant = Dacar::Tuple::from_plaintext(
				"buzzer", "sound", grantee, server_dest_hash, config.primary_hasher()
			);
			if (!state.apply(Dacar::Operation(grant, Dacar::Action::GRANT, stamp + (grantee == hashFromByte(0x04) ? 1 : 0)), (stamp >> 16) + 10000)) {
				fprintf(stderr, "FAIL: could not apply client grant\n");
				kill(authorityPid, SIGTERM);
				return 1;
			}
		}

		Dacar::RnsLinkTransport transport(link, reticulum);
		Dacar::ChallengeClient client(config, state, authoritativePub, transport);

		// 1. bob: granted at the authority -> verified signed ALLOW.
		if (!client.authorize("buzzer", "sound", hashFromByte(0x03))) {
			fprintf(stderr, "FAIL: expected verified ALLOW for bob\n");
			++failures;
		}
		else {
			printf("PASS: bob allowed via signed receipt\n");
		}

		// 2. alice: local pre-check passes, authority signs DENY -> denied.
		if (client.authorize("buzzer", "sound", hashFromByte(0x04))) {
			fprintf(stderr, "FAIL: expected signed DENY for alice\n");
			++failures;
		}
		else {
			printf("PASS: alice denied via signed receipt\n");
		}

		// 3. ungranted relation: denied locally, no wire traffic.
		if (client.authorize("buzzer", "wipe", hashFromByte(0x03))) {
			fprintf(stderr, "FAIL: expected local deny for wipe\n");
			++failures;
		}
		else {
			printf("PASS: ungranted relation denied locally\n");
		}

		// 4. partition: a transport over a dead link defaults to DENY (§8).
		{
			RNS::Link dead({RNS::Type::NONE});
			Dacar::RnsLinkTransport deadTransport(dead, reticulum, 0.5, 0.1);
			Dacar::ChallengeClient partitioned(config, state, authoritativePub, deadTransport);
			if (partitioned.authorize("buzzer", "sound", hashFromByte(0x03))) {
				fprintf(stderr, "FAIL: expected partition deny\n");
				++failures;
			}
			else {
				printf("PASS: partition defaults to deny\n");
			}
		}

		if (link && link.status() != RNS::Type::Link::CLOSED) {
			link.teardown();
		}
		const double cleanupDeadline = RNS::Utilities::OS::time() + 0.3;
		while (RNS::Utilities::OS::time() < cleanupDeadline) {
			reticulum.loop();
			RNS::Utilities::OS::sleep(0.02);
		}

		rc = failures == 0 ? 0 : 1;
	}
	catch (const std::exception& e) {
		fprintf(stderr, "FAIL: exception: %s\n", e.what());
		rc = 1;
	}

	// Stop the authority, then surface its log when the flow failed.
	kill(authorityPid, SIGTERM);
	int status = 0;
	waitpid(authorityPid, &status, 0);
	if (rc != 0) {
		fprintf(stderr, "--- authority output ---\n");
		FILE* log = fopen(authLog.c_str(), "r");
		if (log != nullptr) {
			char buf[512];
			size_t n;
			while ((n = fread(buf, 1, sizeof(buf), log)) > 0) {
				fwrite(buf, 1, n, stderr);
			}
			fclose(log);
		}
		fprintf(stderr, "--- end authority output ---\n");
	}
	::chdir("/tmp");
	::system(("rm -rf '" + clientDir + "'").c_str());
	if (rc == 0) {
		printf("challenge UDP interop: ALL PASS\n");
	}
	return rc;
}
