/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Persistent node store (spec §13, work doc #16 Phase 2).
 *
 * A Store persistently holds a node's configuration (INI, §13.2), HLC
 * (§13.3), CRDT state (§13.4), aliases (§13.5), plaintext ledger (§13.6),
 * issuer public-key cache (§13.7), and the outbox / sent Delta logs
 * (§13.8/§13.9). Persistence itself is delegated to a RecordIo backend:
 *
 *   - PosixRecordIo (PosixStore.h): the §13 loose-file layout over a POSIX
 *     directory — byte-identical to the canonical Python / JS stores, so a
 *     store directory moves between implementations interchangeably (§13.11).
 *   - MicroStoreRecordIo (MicroStoreIo.h): logical records in microStore's
 *     Bitcask-style FileStore — the MCU backend (spec §13 permits alternative
 *     backends when logical records and semantics are preserved).
 *
 * Each CLI / firmware invocation builds a Store, loads what it needs, mutates
 * in memory, and writes back — the offline-first, daemon-free model.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Config.h"
#include "Crdt.h"
#include "Hlc.h"
#include "Naming.h"
#include "Namespace.h"
#include "Verifier.h"

#include "microReticulum/Identity.h"

#include <optional>
#include <string>

namespace Dacar {

	// -- record names (§13.1) --------------------------------------------------

	constexpr const char* CONFIG_RECORD = "config";
	constexpr const char* CLOCK_RECORD = "clock.msgpack";
	constexpr const char* STATE_RECORD = "state.msgpack";
	constexpr const char* ALIASES_RECORD = "aliases";
	constexpr const char* LEDGER_RECORD = "ledger.msgpack";
	constexpr const char* IDENTITIES_RECORD = "identities.msgpack";
	constexpr const char* OUTBOX_RECORD = "outbox.msgpack";
	constexpr const char* SENT_RECORD = "sent.msgpack";
	constexpr const char* IDENTITY_RECORD = "identity";

	// The alias that always names the node's own signing identity (§13.5).
	constexpr const char* SELF_ALIAS = "self";

	// -- raw configuration (§13.2) ----------------------------------------------

	/*
	Raw (unvalidated) node configuration, mirroring the INI record. Empty
	optional-valued fields mean "not configured"; decode_config_ini fills
	defaults exactly like the Python Store.load_config_raw.
	*/
	struct StoreConfig {
		RNS::Bytes primary_salt;
		Vector<RNS::Bytes> legacy_salts;   // at most MAX_LEGACY_SALTS
		Vector<RNS::Bytes> anchors;        // 16-byte Root Trust Anchor hashes
		RNS::Bytes authoritative;          // empty = not configured
		int horizon_days = DEFAULT_DELETION_HORIZON_DAYS;
		std::string rfed_topic = RFED_TOPIC;
		RNS::Bytes rfed_node;              // empty = not configured
		RNS::Bytes lxmf_proprietor;        // empty = not configured
	};

	/*
	Encode a StoreConfig as the INI text Python's configparser writes:
	sections [salt]/[trust]/[policy]/[rfed] (+ lazy [lxmf]) in fixed order,
	`key = value`, lowercase hex, a blank line after every section.
	*/
	std::string encode_config_ini(const StoreConfig& config);

	/*
	Decode INI bytes into a StoreConfig. Mirrors Python's configparser +
	Store.load_config_raw: option keys are case-insensitive, `=` and `:`
	delimiters, full-line `#`/`;` comments, missing options fall back to
	defaults (primary salt -> the fail-open DEFAULT_SALT).
	Throws std::invalid_argument on malformed hex or a bad horizon integer.
	*/
	StoreConfig decode_config_ini(const RNS::Bytes& data);

	// -- aliases (§13.5) ---------------------------------------------------------

	// One rnns alias line: a 16-byte hash with one or more names and a note.
	struct AliasEntry {
		RNS::Bytes hash;
		Vector<std::string> names;
		std::optional<std::string> note;
	};

	/*
	The in-memory form of the `aliases` file (rnns `hash name [# note]`).
	One hash may carry several names; names are unique across the registry.
	The registry is a naming layer only — it never stores public keys.
	*/
	class AliasRegistry {

	public:
		Vector<AliasEntry> entries;

		AliasRegistry() = default;
		~AliasRegistry() = default;

		/*
		Parse rnns `hash name [# note]` lines. Blank lines and lines whose
		first token is not a 32-hex hash are skipped; a trailing `# note` is
		captured per entry; duplicate hashes merge their names.
		*/
		static AliasRegistry parse(const std::string& text);

		// Render back to rnns `hash name [# note]` lines (trailing newline;
		// an empty registry serializes to zero bytes).
		std::string serialize() const;

		// Render stripped of dacar-local `# note` annotations.
		std::string serialize_for_rnns() const;

		// Return the 16-byte hash aliased to `name`, or nullptr.
		const RNS::Bytes* resolve(const char* name) const;

		// All names bound to `hash` (may be empty).
		Vector<std::string> names_for(const RNS::Bytes& hash) const;

		// First name bound to `hash`, or nullptr.
		const std::string* primary_name(const RNS::Bytes& hash) const;

		// Add `name` for `hash`; set `note` when provided.
		void add(const char* name, const RNS::Bytes& hash, const char* note = nullptr);

		// Remove `name` from its entry. Returns true if it existed.
		bool remove(const char* name);

		// Point the `self` alias at `hash` (replacing any prior binding).
		void set_self(const RNS::Bytes& hash);

	private:
		AliasEntry* entry_for(const RNS::Bytes& hash);
		const AliasEntry* entry_for(const RNS::Bytes& hash) const;

	};

	// -- plaintext ledger (§13.6) --------------------------------------------------

	// One ledger row: the plaintext annotation for a locally-issued grant.
	// Absent optionals serialize as msgpack nil (Python `None` parity).
	struct LedgerRow {
		std::optional<std::string> object;
		std::optional<std::string> relation;
		std::optional<bool> wildcard;
		uint64_t first_seen = 0;   // physical (high-48) HLC timestamp
	};

	/*
	Plaintext ledger keyed by the hex-encoded Tuple Hash (§6.1). Records the
	plaintext (object, relation, wildcard) for grants issued locally so
	inspections can render readable rows; network-received opaque deltas have
	no plaintext and stay hashed. Insertion order is preserved (Python dict
	parity) — ledger.msgpack serializes in it.
	*/
	class Ledger {

	public:
		Ledger() = default;
		~Ledger() = default;

		static std::string key_for(const RNS::Bytes& tuple_hash);

		// Record or refresh the plaintext for a tuple hash (keeps the
		// earliest first_seen, mirroring the Python Ledger.record).
		void record(
			const RNS::Bytes& tuple_hash,
			const char* object_id,
			const char* relation,
			bool wildcard,
			uint64_t first_seen
		);

		/*
		Manually name an opaque tuple's plaintext (nullptr / absent leaves a
		field unchanged). Returns true if the row exists.
		*/
		bool annotate(
			const RNS::Bytes& tuple_hash,
			const std::optional<std::string>& object_id = {},
			const std::optional<std::string>& relation = {},
			const std::optional<bool>& wildcard = {}
		);

		// Get or create a (possibly empty) ledger row for a tuple hash.
		LedgerRow& ensure(const RNS::Bytes& tuple_hash);

		// The row for a tuple hash, or nullptr when absent.
		const LedgerRow* lookup(const RNS::Bytes& tuple_hash) const;

		size_t size() const { return _rows.size(); }

		// (tuple-hash-hex, row) pairs in insertion order.
		const Vector<std::pair<std::string, LedgerRow>>& rows() const { return _rows; }

	private:
		Vector<std::pair<std::string, LedgerRow>> _rows;
		Map<std::string, size_t> _index;

		friend Ledger decode_ledger_payload(const RNS::Bytes& data);

	};

	// -- record codecs (msgpack bytes are Python-canonical) --------------------------

	// §13.3: {"last_ms": uint, "logical": uint} (str keys, insertion order).
	RNS::Bytes encode_clock_payload(const Clock& clock);
	// Tolerant decode: missing record / non-map / missing keys -> Clock().
	Clock decode_clock_payload(const RNS::Bytes& data);

	// §13.6: {tuple_hash_hex: {object, relation, wildcard, first_seen}}.
	RNS::Bytes encode_ledger_payload(const Ledger& ledger);
	// Tolerant decode: non-map payloads yield an empty ledger.
	Ledger decode_ledger_payload(const RNS::Bytes& data);

	// §13.7: {issuer_hash_hex: 32-byte Ed25519 public key} — single-identity
	// entries only, in registration order; threshold-group keysets are skipped.
	RNS::Bytes encode_keyring_payload(const Keyring& keyring);
	// Tolerant decode: wrong-length values and malformed hashes are dropped.
	Keyring decode_keyring_payload(const RNS::Bytes& data);

	// §13.8/§13.9: array of raw §5.3 payload bytes.
	RNS::Bytes encode_payload_list(const Vector<RNS::Bytes>& payloads);
	// Corrupted or non-array payloads yield an empty list (must not crash).
	Vector<RNS::Bytes> decode_payload_list(const RNS::Bytes& data);

	// -- record backend --------------------------------------------------------------

	/*
	Backend-neutral record storage: named blobs. The two implementations are
	PosixRecordIo (§13 loose files, byte-identical) and MicroStoreRecordIo
	(microStore FileStore records for MCU flash).
	*/
	class RecordIo {

	public:
		virtual ~RecordIo() = default;

		// Read a record into `data`; returns false when it does not exist.
		virtual bool read(const char* name, RNS::Bytes& data) = 0;

		/*
		Write a record. `secret` selects 0600 vs 0644 where file modes exist
		(POSIX backend); flash backends ignore it.
		*/
		virtual bool write(const char* name, const RNS::Bytes& data, bool secret) = 0;

		/*
		Filesystem path backing `name`, or nullptr when the backend is not
		path-based (used for the §13.10 identity record, which RNS::Identity
		loads/saves through real files).
		*/
		virtual const char* path_for(const char* name) const {
			(void)name;
			return nullptr;
		}

	};

	// -- the store ---------------------------------------------------------------------

	class StoreError : public std::runtime_error {
	public:
		explicit StoreError(const std::string& message)
			: std::runtime_error(message)
		{}
	};

	class Store {

	public:
		explicit Store(RecordIo& io)
			: _io(io)
		{}
		~Store() = default;

		// True once the store holds a config record (i.e. was initialized).
		bool exists() const;

		/*
		Bootstrap a fresh node store (§13.11 `init`): writes the INI config
		(with the node's own identity as the root trust anchor — the v1
		bootstrap), empty state, clock, and ledger records, and the aliases
		record naming the node `self`. An empty `salt` generates a fresh
		random Privacy Salt; a wrong-length salt throws std::invalid_argument.
		The lazy records (identities/outbox/sent) are NOT created, matching
		Python `init`.
		*/
		static bool init(
			RecordIo& io,
			const RNS::Bytes& own_identity_hash,
			const RNS::Bytes& salt = RNS::Bytes(),
			int horizon_days = DEFAULT_DELETION_HORIZON_DAYS,
			const char* rfed_topic = RFED_TOPIC
		);

		// -- config (§13.2) -----------------------------------------------------
		// Load the raw config; returns false when uninitialized.
		bool load_config_raw(StoreConfig& config) const;
		bool save_config(const StoreConfig& config);

		/*
		Build a validated Config from the INI. Throws StoreError when
		uninitialized or no Root Trust Anchors are configured.
		*/
		Config load_config() const;

		// -- clock (§13.3) --------------------------------------------------------
		// Load the persisted HLC (a fresh Clock when absent/corrupt). Save
		// after issuing operations: a reboot must never rewind the HLC.
		Clock load_clock() const;
		bool save_clock(const Clock& clock);

		// -- state (§13.4) --------------------------------------------------------
		/*
		Load the CRDT snapshot (trusted-local-only — the record this node
		wrote via save_state; network Deltas go through DeltaReceiver).
		Returns an empty StateVector when absent. Throws std::invalid_argument
		on a malformed payload (corruption of trusted-local state is fatal,
		matching Python).
		*/
		StateVector load_state(int deletion_horizon_days = DEFAULT_DELETION_HORIZON_DAYS) const;
		bool save_state(const StateVector& state);

		// -- aliases (§13.5) --------------------------------------------------------
		AliasRegistry load_aliases() const;
		bool save_aliases(const AliasRegistry& aliases);

		// -- ledger (§13.6) -----------------------------------------------------------
		Ledger load_ledger() const;
		bool save_ledger(const Ledger& ledger);

		// -- issuer cache (§13.7) ------------------------------------------------------
		// The durable issuer public-key cache; empty Keyring when absent.
		Keyring load_keyring() const;
		bool save_keyring(const Keyring& keyring);

		/*
		Verify-on-ingest keyring: the persisted cache plus the node's own
		signing identity, so self-signed Deltas always verify.
		*/
		Keyring keyring_for_verify(const RNS::Bytes& own_identity_hash, const RNS::Bytes& own_sig_pub) const;

		// -- outbox / sent box (§13.8, §13.9) ---------------------------------------------
		// Locally-issued, not-yet-published Delta payloads in issuance order.
		Vector<RNS::Bytes> load_outbox() const;
		bool save_outbox(const Vector<RNS::Bytes>& payloads);
		// Published Delta payloads (durable replay log), in publication order.
		Vector<RNS::Bytes> load_sent() const;
		bool save_sent(const Vector<RNS::Bytes>& payloads);

		// -- node signing identity (§13.10) -------------------------------------------------
		/*
		Load / persist the node's own signing identity at a filesystem path
		(RecordIo::path_for(IDENTITY_RECORD)). The 64-byte private-key format
		(X25519 ‖ Ed25519) is shared with the Python `identity` record, so a
		store directory initialized by either implementation carries a usable
		signing identity for both. Saving tightens the mode to 0600.
		*/
		static bool load_identity(const char* path, RNS::Identity& identity);
		static bool save_identity(const char* path, RNS::Identity& identity);

	private:
		RecordIo& _io;

	};

}
