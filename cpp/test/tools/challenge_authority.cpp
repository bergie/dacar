/*
 * Dacar §8 challenge authority — a standalone Strict Consistency server.
 *
 * Runs an AuthoritativeServer on the `dacar.auth.v1` destination over a
 * point-to-point UDP interface, announces, and answers challenge requests
 * with signed Freshness Receipts. Used by the two-process interop tests
 * (challenge_udp_test.cpp, and the Python interop scripts) and handy for
 * manual testing against a real client:
 *
 *   challenge_authority <listen_port> <remote_port> <peer_file> [salt_hex]
 *
 * The authority self-generates its identity, grants <bob> the
 * `buzzer:sound` action from its own anchor, and — once announced — writes
 * `<dest_hash_hex> <ed25519_pub_hex>` to <peer_file> for the client to
 * discover. Run until killed.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Dacar.h"
#include "Dacar/RnsChallenge.h"
#include "UdpPointInterface.h"

#include <microStore/Adapters/UniversalFileSystem.h>

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

static RNS::Bytes hashFromByte(uint8_t fill) {
	RNS::Bytes out;
	memset(out.writable(16), fill, 16);
	return out;
}

int main(int argc, char** argv) {
	if (argc < 4) {
		fprintf(stderr, "usage: %s <listen_port> <remote_port> <peer_file> [salt_hex]\n", argv[0]);
		return 2;
	}
	const int listenPort = atoi(argv[1]);
	const int remotePort = atoi(argv[2]);
	const char* peerFile = argv[3];
	const char* saltHex = argc > 4 ? argv[4] : "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	char tmpl[] = "/tmp/dacar-authority-XXXXXX";
	char* dir = mkdtemp(tmpl);
	if (!dir) {
		fprintf(stderr, "mkdtemp failed\n");
		return 1;
	}
	// microStore's PosixFileSystem is CWD-relative on native.
	if (chdir(dir) != 0) {
		fprintf(stderr, "chdir failed\n");
		return 1;
	}

	try {
		static microStore::Adapters::UniversalFileSystem filesystem;
		RNS::Utilities::OS::register_filesystem(filesystem);

		static UdpPointInterface* udp = new UdpPointInterface("authority-udp", listenPort, "127.0.0.1", remotePort);
		if (!udp->start()) {
			fprintf(stderr, "failed to bind UDP port %d\n", listenPort);
			return 1;
		}
		RNS::Interface udp_handle(udp);
		RNS::Transport::register_interface(udp_handle);

		RNS::Reticulum reticulum = RNS::Reticulum();
		reticulum.transport_enabled(true);
		reticulum.start();

		// The authority's own identity is the root trust anchor (v1 bootstrap)
		// and the Freshness Receipt signer.
		RNS::Identity identity = RNS::Identity();
		RNS::Bytes salt;
		salt.assignHex(saltHex);

		Dacar::Set<RNS::Bytes> anchors{identity.hash()};
		Dacar::Config config(anchors, salt, {}, {}, identity.hash());
		Dacar::StateVector state(config.deletion_horizon_days());

		// Grant <bob> the buzzer:sound action from the anchor.
		const RNS::Bytes bob = hashFromByte(0x03);
		const uint64_t stamp = 0x0000123456780000ULL;
		Dacar::Tuple grant = Dacar::Tuple::from_plaintext(
			"buzzer", "sound", bob, identity.hash(), config.primary_hasher()
		);
		if (!state.apply(Dacar::Operation(grant, Dacar::Action::GRANT, stamp), (stamp >> 16) + 10000)) {
			fprintf(stderr, "failed to apply grant\n");
			return 1;
		}

		// Sign Freshness Receipts with the authority identity's own Ed25519
		// key — clients verify against the public half announced on the path.
		auto serverKey = RNS::Cryptography::Ed25519PrivateKey::from_private_bytes(
			identity.get_private_key().mid(32)
		);
		Dacar::AuthoritativeServer authority(config, state, serverKey);
		Dacar::RnsChallengeServer challengeServer(identity, authority);

		printf("authority destination: %s\n", challengeServer.destination_hash().toHex().c_str());
		printf("authority ed25519 pub: %s\n", identity.get_public_key().mid(32).toHex().c_str());

		// Announce until the client sees us, then publish the discovery file.
		for (int i = 0; i < 50 && _running; i++) {
			challengeServer.announce();
			const double deadline = RNS::Utilities::OS::time() + 0.2;
			while (RNS::Utilities::OS::time() < deadline && _running) {
				reticulum.loop();
				RNS::Utilities::OS::sleep(0.02);
			}
			FILE* fh = fopen(peerFile, "w");
			if (fh != nullptr) {
				fprintf(fh, "%s %s\n",
					challengeServer.destination_hash().toHex().c_str(),
					identity.get_public_key().mid(32).toHex().c_str());
				fclose(fh);
				break;
			}
		}
		printf("authority ready\n");
		fflush(stdout);

		while (_running) {
			reticulum.loop();
			RNS::Utilities::OS::sleep(0.02);
		}

		// Scratch dir is disposable; leave it for post-mortem on failure.
		printf("authority exiting\n");
		return 0;
	}
	catch (const std::exception& e) {
		fprintf(stderr, "authority exception: %s\n", e.what());
		return 1;
	}
}
