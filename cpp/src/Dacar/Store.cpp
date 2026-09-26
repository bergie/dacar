/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "Store.h"

#include "microReticulum/Cryptography/Random.h"
#include "microReticulum/Identity.h"
#include "microReticulum/Log.h"

#include <MsgPack.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

#if defined(DACAR_POSIX_STORE)
#include <sys/stat.h>
#endif

namespace Dacar {

namespace {

	// Consume one value of any primitive msgpack shape so decoding stays
	// aligned; returns false for containers (no generic skip exists).
	bool skipValue(MsgPack::Unpacker& u) {
		if (u.isUInt()) {
			u.unpackUInt<uint64_t>();
			return true;
		}
		if (u.isInt()) {
			u.unpackInt<int64_t>();
			return true;
		}
		if (u.isBool()) {
			u.unpackBool();
			return true;
		}
		if (u.isStr()) {
			MsgPack::str_t s;
			u.deserialize(s);
			return true;
		}
		if (u.isBin()) {
			MsgPack::bin_t<uint8_t> b;
			u.deserialize(b);
			return true;
		}
		if (u.isNil()) {
			u.unpackNil();
			return true;
		}
		return false;
	}

}

// -- hex helpers -----------------------------------------------------------------

namespace {

	std::string toLowerHex(const RNS::Bytes& data) {
		return data.toHex();
	}

	std::string trimCopy(const std::string& value) {
		size_t begin = 0;
		while (begin < value.size() && std::isspace((unsigned char)value[begin])) {
			begin++;
		}
		size_t end = value.size();
		while (end > begin && std::isspace((unsigned char)value[end - 1])) {
			end--;
		}
		return value.substr(begin, end - begin);
	}

	int hexNibble(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		}
		return -1;
	}

	// Parse a hex string (optional 0x prefix, case-insensitive, surrounding
	// whitespace tolerated) into exactly `length` bytes. Python `_hex` parity.
	RNS::Bytes parseHex(const std::string& value, size_t length, const char* what) {
		std::string clean = trimCopy(value);
		if (clean.size() >= 2 && clean[0] == '0' && (clean[1] == 'x' || clean[1] == 'X')) {
			clean = clean.substr(2);
		}
		if (clean.size() != length * 2) {
			throw std::invalid_argument(
				std::string(what) + " must be " + std::to_string(length)
				+ " bytes (" + std::to_string(length * 2) + " hex), got " + std::to_string(clean.size() / 2)
			);
		}
		RNS::Bytes out;
		uint8_t* buf = out.writable(length);
		for (size_t i = 0; i < clean.size(); i += 2) {
			int hi = hexNibble(clean[i]);
			int lo = hexNibble(clean[i + 1]);
			if (hi < 0 || lo < 0) {
				throw std::invalid_argument(std::string(what) + " is not valid hex");
			}
			buf[i / 2] = (uint8_t)((hi << 4) | lo);
		}
		return out;
	}

	bool isHexLen(const std::string& value, size_t hexLength) {
		if (value.size() != hexLength) {
			return false;
		}
		for (char c : value) {
			if (hexNibble(c) < 0) {
				return false;
			}
		}
		return true;
	}

} // namespace (file-local helpers)

// -- raw configuration (§13.2) ---------------------------------------------------

std::string encode_config_ini(const StoreConfig& config) {
	std::string out;
	out.reserve(256);
	out += "[salt]\n";
	out += "primary = " + toLowerHex(config.primary_salt) + "\n";
	for (size_t i = 0; i < config.legacy_salts.size() && i < MAX_LEGACY_SALTS; i++) {
		out += "legacy" + std::to_string(i) + " = " + toLowerHex(config.legacy_salts[i]) + "\n";
	}
	out += "\n[trust]\n";
	std::string anchors;
	for (const auto& anchor : config.anchors) {
		if (!anchors.empty()) {
			anchors += ", ";
		}
		anchors += toLowerHex(anchor);
	}
	out += "anchors = " + anchors + "\n";
	if (config.authoritative) {
		out += "authoritative = " + toLowerHex(config.authoritative) + "\n";
	}
	out += "\n[policy]\n";
	out += "deletion_horizon_days = " + std::to_string(config.horizon_days) + "\n";
	out += "\n[rfed]\n";
	out += "topic = " + config.rfed_topic + "\n";
	if (config.rfed_node) {
		out += "node = " + toLowerHex(config.rfed_node) + "\n";
	}
	// [lxmf] is written only when a proprietor is set (lazy section —
	// configparser writes sections only when populated).
	if (config.lxmf_proprietor) {
		out += "\n[lxmf]\n";
		out += "proprietor = " + toLowerHex(config.lxmf_proprietor) + "\n";
	}
	out += "\n";
	return out;
}

namespace {

	// Minimal INI model: ordered section -> (lowercased key -> value).
	struct IniSection {
		std::string name;
		Vector<std::pair<std::string, std::string>> options;
	};

	const std::string* iniGet(const Vector<IniSection>& sections, const char* section, const char* option) {
		for (const auto& sec : sections) {
			if (sec.name != section) {
				continue;
			}
			for (const auto& kv : sec.options) {
				if (kv.first == option) {
					return &kv.second;
				}
			}
		}
		return nullptr;
	}

	// Parse INI text the way Python's configparser reads it: `[section]`
	// headers, `key = value` or `key: value` (first delimiter wins), full-line
	// `#`/`;` comments, blank lines skipped, option keys lowercased.
	Vector<IniSection> parseIni(const std::string& text) {
		Vector<IniSection> sections;
		IniSection* current = nullptr;
		size_t pos = 0;
		while (pos <= text.size()) {
			size_t eol = text.find('\n', pos);
			std::string line = text.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
			line = trimCopy(line);
			pos = (eol == std::string::npos) ? text.size() + 1 : eol + 1;
			if (line.empty() || line[0] == '#' || line[0] == ';') {
				continue;
			}
			if (line.front() == '[' && line.back() == ']') {
				IniSection section;
				section.name = trimCopy(line.substr(1, line.size() - 2));
				sections.push_back(section);
				current = &sections.back();
				continue;
			}
			if (current == nullptr) {
				continue;
			}
			size_t delim = line.find_first_of("=:");
			if (delim == std::string::npos || delim == 0) {
				continue;
			}
			std::string key = trimCopy(line.substr(0, delim));
			std::string value = trimCopy(line.substr(delim + 1));
			for (auto& c : key) {
				c = (char)std::tolower((unsigned char)c);
			}
			current->options.emplace_back(key, value);
		}
		return sections;
	}

} // namespace

StoreConfig decode_config_ini(const RNS::Bytes& data) {
	Vector<IniSection> sections = parseIni(std::string((const char*)data.data(), data.size()));

	StoreConfig config;

	// [salt]: primary falls back to the fail-open default (Python parity).
	const std::string* primary = iniGet(sections, "salt", "primary");
	config.primary_salt = primary
		? parseHex(*primary, SALT_SIZE, "primary")
		: DEFAULT_SALT();
	for (size_t i = 0; i < MAX_LEGACY_SALTS; i++) {
		char key[16];
		snprintf(key, sizeof(key), "legacy%u", (unsigned)i);
		const std::string* legacy = iniGet(sections, "salt", key);
		if (legacy != nullptr) {
			config.legacy_salts.push_back(parseHex(*legacy, SALT_SIZE, key));
		}
	}

	const std::string* anchors = iniGet(sections, "trust", "anchors");
	if (anchors != nullptr) {
		std::string list = trimCopy(*anchors);
		size_t pos = 0;
		while (pos <= list.size()) {
			size_t comma = list.find(',', pos);
			std::string item = trimCopy(
				list.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos)
			);
			if (!item.empty()) {
				config.anchors.push_back(parseHex(item, HASH_SIZE, "anchors"));
			}
			if (comma == std::string::npos) {
				break;
			}
			pos = comma + 1;
		}
	}

	const std::string* authoritative = iniGet(sections, "trust", "authoritative");
	if (authoritative != nullptr) {
		config.authoritative = parseHex(*authoritative, HASH_SIZE, "authoritative");
	}

	const std::string* horizon = iniGet(sections, "policy", "deletion_horizon_days");
	if (horizon != nullptr) {
		std::string clean = trimCopy(*horizon);
		char* end = nullptr;
		errno = 0;
		long parsed = strtol(clean.c_str(), &end, 10);
		if (end == clean.c_str() || *end != '\0' || errno == ERANGE) {
			throw std::invalid_argument("deletion_horizon_days is not an integer");
		}
		config.horizon_days = (int)parsed;
	}

	const std::string* topic = iniGet(sections, "rfed", "topic");
	if (topic != nullptr) {
		config.rfed_topic = trimCopy(*topic);
	}

	const std::string* node = iniGet(sections, "rfed", "node");
	if (node != nullptr) {
		config.rfed_node = parseHex(*node, HASH_SIZE, "node");
	}

	const std::string* proprietor = iniGet(sections, "lxmf", "proprietor");
	if (proprietor != nullptr) {
		config.lxmf_proprietor = parseHex(*proprietor, HASH_SIZE, "proprietor");
	}

	return config;
}

// -- aliases (§13.5) ---------------------------------------------------------------

namespace {

	bool splitNames(const std::string& head, Vector<std::string>& names) {
		size_t pos = 0;
		while (pos <= head.size()) {
			size_t space = head.find(' ', pos);
			size_t tab = head.find('\t', pos);
			size_t sep = std::min(
				space == std::string::npos ? std::string::npos : space,
				tab == std::string::npos ? std::string::npos : tab
			);
			std::string token = head.substr(pos, sep == std::string::npos ? std::string::npos : sep - pos);
			if (!token.empty()) {
				names.push_back(token);
			}
			if (sep == std::string::npos) {
				break;
			}
			pos = sep + 1;
		}
		return !names.empty();
	}

} // namespace

/*static*/ AliasRegistry AliasRegistry::parse(const std::string& text) {
	AliasRegistry registry;
	size_t pos = 0;
	while (pos <= text.size()) {
		size_t eol = text.find('\n', pos);
		std::string raw = text.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
		pos = (eol == std::string::npos) ? text.size() + 1 : eol + 1;
		std::string line = trimCopy(raw);
		if (line.empty()) {
			continue;
		}
		// Split off a trailing `# note` (dacar-local).
		std::string head = line;
		std::optional<std::string> note;
		size_t hash = line.find('#');
		if (hash != std::string::npos) {
			head = line.substr(0, hash);
			std::string noteText = trimCopy(line.substr(hash + 1));
			if (!noteText.empty()) {
				note = noteText;
			}
		}
		head = trimCopy(head);
		size_t sep = head.find_first_of(" \t");
		std::string hashHex = trimCopy(sep == std::string::npos ? head : head.substr(0, sep));
		std::string rest = sep == std::string::npos ? "" : head.substr(sep + 1);
		// Only 32-hex (16-byte) first tokens are real alias lines.
		if (!isHexLen(hashHex, HASH_SIZE * 2)) {
			continue;
		}
		Vector<std::string> names;
		if (!splitNames(rest, names)) {
			continue;
		}
		RNS::Bytes hashBytes = parseHex(hashHex, HASH_SIZE, "alias hash");
		AliasEntry* existing = registry.entry_for(hashBytes);
		if (existing != nullptr) {
			for (const auto& name : names) {
				bool known = false;
				for (const auto& n : existing->names) {
					if (n == name) {
						known = true;
						break;
					}
				}
				if (!known) {
					existing->names.push_back(name);
				}
			}
			if (note.has_value()) {
				existing->note = note;
			}
		}
		else {
			AliasEntry entry;
			entry.hash = hashBytes;
			entry.names = names;
			entry.note = note;
			registry.entries.push_back(entry);
		}
	}
	return registry;
}

std::string AliasRegistry::serialize() const {
	std::string out;
	for (const auto& entry : entries) {
		std::string line = toLowerHex(entry.hash);
		for (const auto& name : entry.names) {
			line += " " + name;
		}
		if (entry.note.has_value()) {
			line += "  # " + *entry.note;
		}
		out += line + "\n";
	}
	return out;
}

std::string AliasRegistry::serialize_for_rnns() const {
	std::string out;
	for (const auto& entry : entries) {
		if (entry.names.empty()) {
			continue;
		}
		std::string line = toLowerHex(entry.hash);
		for (const auto& name : entry.names) {
			line += " " + name;
		}
		out += line + "\n";
	}
	return out;
}

const RNS::Bytes* AliasRegistry::resolve(const char* name) const {
	if (name == nullptr) {
		return nullptr;
	}
	for (const auto& entry : entries) {
		for (const auto& n : entry.names) {
			if (n == name) {
				return &entry.hash;
			}
		}
	}
	return nullptr;
}

Vector<std::string> AliasRegistry::names_for(const RNS::Bytes& hash) const {
	const AliasEntry* entry = entry_for(hash);
	return entry ? entry->names : Vector<std::string>();
}

const std::string* AliasRegistry::primary_name(const RNS::Bytes& hash) const {
	const AliasEntry* entry = entry_for(hash);
	if (entry == nullptr || entry->names.empty()) {
		return nullptr;
	}
	return &entry->names.front();
}

void AliasRegistry::add(const char* name, const RNS::Bytes& hash, const char* note) {
	AliasEntry* entry = entry_for(hash);
	if (entry != nullptr) {
		for (const auto& n : entry->names) {
			if (n == name) {
				if (note != nullptr) {
					entry->note = std::string(note);
				}
				return;
			}
		}
		entry->names.push_back(name);
		if (note != nullptr) {
			entry->note = std::string(note);
		}
		return;
	}
	AliasEntry fresh;
	fresh.hash = hash;
	fresh.names.push_back(name);
	if (note != nullptr) {
		fresh.note = std::string(note);
	}
	entries.push_back(fresh);
}

bool AliasRegistry::remove(const char* name) {
	for (auto it = entries.begin(); it != entries.end(); ++it) {
		for (auto nit = it->names.begin(); nit != it->names.end(); ++nit) {
			if (*nit == name) {
				it->names.erase(nit);
				if (it->names.empty()) {
					entries.erase(it);
				}
				return true;
			}
		}
	}
	return false;
}

void AliasRegistry::set_self(const RNS::Bytes& hash) {
	for (auto it = entries.begin(); it != entries.end();) {
		bool removed = false;
		for (auto nit = it->names.begin(); nit != it->names.end();) {
			if (*nit == SELF_ALIAS) {
				nit = it->names.erase(nit);
				removed = true;
			}
			else {
				++nit;
			}
		}
		if (it->names.empty()) {
			it = entries.erase(it);
		}
		else {
			if (removed) {
				// self was the only name case handled above; others keep going
			}
			++it;
		}
	}
	add(SELF_ALIAS, hash);
}

AliasEntry* AliasRegistry::entry_for(const RNS::Bytes& hash) {
	for (auto& entry : entries) {
		if (entry.hash == hash) {
			return &entry;
		}
	}
	return nullptr;
}

const AliasEntry* AliasRegistry::entry_for(const RNS::Bytes& hash) const {
	for (const auto& entry : entries) {
		if (entry.hash == hash) {
			return &entry;
		}
	}
	return nullptr;
}

// -- plaintext ledger (§13.6) ---------------------------------------------------------

/*static*/ std::string Ledger::key_for(const RNS::Bytes& tuple_hash) {
	return tuple_hash.toHex();
}

void Ledger::record(
	const RNS::Bytes& tuple_hash,
	const char* object_id,
	const char* relation,
	bool wildcard,
	uint64_t first_seen
) {
	const std::string key = key_for(tuple_hash);
	auto it = _index.find(key);
	if (it == _index.end()) {
		LedgerRow row;
		row.object = std::string(object_id);
		row.relation = std::string(relation);
		row.wildcard = wildcard;
		row.first_seen = first_seen;
		_index[key] = _rows.size();
		_rows.emplace_back(key, row);
		return;
	}
	LedgerRow& row = _rows[it->second].second;
	row.object = std::string(object_id);
	row.relation = std::string(relation);
	row.wildcard = wildcard;
	if (first_seen < row.first_seen) {
		row.first_seen = first_seen;
	}
}

bool Ledger::annotate(
	const RNS::Bytes& tuple_hash,
	const std::optional<std::string>& object_id,
	const std::optional<std::string>& relation,
	const std::optional<bool>& wildcard
) {
	auto it = _index.find(key_for(tuple_hash));
	if (it == _index.end()) {
		return false;
	}
	LedgerRow& row = _rows[it->second].second;
	if (object_id.has_value()) {
		row.object = object_id;
	}
	if (relation.has_value()) {
		row.relation = relation;
	}
	if (wildcard.has_value()) {
		row.wildcard = wildcard;
	}
	return true;
}

LedgerRow& Ledger::ensure(const RNS::Bytes& tuple_hash) {
	const std::string key = key_for(tuple_hash);
	auto it = _index.find(key);
	if (it != _index.end()) {
		return _rows[it->second].second;
	}
	LedgerRow row;
	row.first_seen = 0;
	_index[key] = _rows.size();
	_rows.emplace_back(key, row);
	return _rows.back().second;
}

const LedgerRow* Ledger::lookup(const RNS::Bytes& tuple_hash) const {
	auto it = _index.find(key_for(tuple_hash));
	if (it == _index.end()) {
		return nullptr;
	}
	return &_rows[it->second].second;
}

// -- record codecs ----------------------------------------------------------------------

RNS::Bytes encode_clock_payload(const Clock& clock) {
	MsgPack::Packer p;
	p.packMapSize(2);
	p.pack(std::string("last_ms"));
	p.pack(clock.last_ms());
	p.pack(std::string("logical"));
	p.pack(clock.logical());
	return RNS::Bytes(p.data(), p.size());
}

Clock decode_clock_payload(const RNS::Bytes& data) {
	uint64_t lastMs = 0;
	uint64_t logical = 0;
	MsgPack::Unpacker u;
	if (data && u.feed(data.data(), data.size()) && u.isMap()) {
		size_t count = u.unpackMapSize();
		for (size_t i = 0; i < count; i++) {
			MsgPack::str_t key;
			if (!u.deserialize(key)) {
				break;
			}
			if (key == "last_ms" && u.isUInt()) {
				lastMs = u.unpackUInt<uint64_t>();
			}
			else if (key == "logical" && u.isUInt()) {
				logical = u.unpackUInt<uint64_t>();
			}
			else if (!skipValue(u)) {
				break;
			}
		}
	}
	return Clock(lastMs, logical);
}

RNS::Bytes encode_ledger_payload(const Ledger& ledger) {
	MsgPack::Packer p;
	p.packMapSize(ledger.rows().size());
	for (const auto& [key, row] : ledger.rows()) {
		p.pack(key);
		p.packMapSize(4);
		p.pack(std::string("object"));
		if (row.object.has_value()) {
			p.pack(*row.object);
		}
		else {
			p.packNil();
		}
		p.pack(std::string("relation"));
		if (row.relation.has_value()) {
			p.pack(*row.relation);
		}
		else {
			p.packNil();
		}
		p.pack(std::string("wildcard"));
		if (row.wildcard.has_value()) {
			p.pack(*row.wildcard);
		}
		else {
			p.packNil();
		}
		p.pack(std::string("first_seen"));
		p.pack(row.first_seen);
	}
	return RNS::Bytes(p.data(), p.size());
}

Ledger decode_ledger_payload(const RNS::Bytes& data) {
	Ledger ledger;
	MsgPack::Unpacker u;
	if (!(data && u.feed(data.data(), data.size()) && u.isMap())) {
		return ledger;
	}
	size_t count = u.unpackMapSize();
	for (size_t i = 0; i < count; i++) {
		MsgPack::str_t key;
		if (!u.deserialize(key)) {
			break;
		}
		LedgerRow row;
		if (u.isMap()) {
			size_t fields = u.unpackMapSize();
			for (size_t f = 0; f < fields; f++) {
				MsgPack::str_t field;
				if (!u.deserialize(field)) {
					break;
				}
				if (field == "object" && u.isStr()) {
					MsgPack::str_t value;
					u.deserialize(value);
					row.object = value;
				}
				else if (field == "relation" && u.isStr()) {
					MsgPack::str_t value;
					u.deserialize(value);
					row.relation = value;
				}
				else if (field == "wildcard" && u.isBool()) {
					row.wildcard = u.unpackBool();
				}
				else if (field == "first_seen" && u.isUInt()) {
					row.first_seen = u.unpackUInt<uint64_t>();
				}
				else if (!skipValue(u)) {
					break;
				}
			}
		}
		else if (!skipValue(u)) {
			break; // non-map value -> alignment lost
		}
		ledger._rows.emplace_back(key, row);
		ledger._index[key] = ledger._rows.size() - 1;
	}
	return ledger;
}

RNS::Bytes encode_keyring_payload(const Keyring& keyring) {
	size_t singles = 0;
	for (const auto& [hash, keyset] : keyring.entries()) {
		if (keyset.threshold() == 1 && keyset.member_public_keys().size() == 1) {
			singles++;
		}
	}
	MsgPack::Packer p;
	p.packMapSize(singles);
	for (const auto& [hash, keyset] : keyring.entries()) {
		if (keyset.threshold() == 1 && keyset.member_public_keys().size() == 1) {
			p.pack(hash.toHex());
			const RNS::Bytes& pub = keyset.member_public_keys().front();
			p.packBinary(pub.data(), pub.size());
		}
	}
	return RNS::Bytes(p.data(), p.size());
}

Keyring decode_keyring_payload(const RNS::Bytes& data) {
	Keyring keyring;
	MsgPack::Unpacker u;
	if (!(data && u.feed(data.data(), data.size()) && u.isMap())) {
		return keyring;
	}
	size_t count = u.unpackMapSize();
	for (size_t i = 0; i < count; i++) {
		MsgPack::str_t hashHex;
		if (!u.deserialize(hashHex)) {
			break;
		}
		MsgPack::bin_t<uint8_t> pub;
		if (!u.deserialize(pub) || pub.size() != PUBLIC_KEY_SIZE) {
			continue; // wrong-length entries are dropped on load (§13.7)
		}
		if (!isHexLen(hashHex, HASH_SIZE * 2)) {
			continue; // malformed hash -> skip
		}
		try {
			keyring.register_single(parseHex(hashHex, HASH_SIZE, "issuer hash"), RNS::Bytes(pub.data(), pub.size()));
		}
		catch (const std::invalid_argument&) {
			continue;
		}
	}
	return keyring;
}

RNS::Bytes encode_payload_list(const Vector<RNS::Bytes>& payloads) {
	MsgPack::Packer p;
	p.packArraySize(payloads.size());
	for (const auto& payload : payloads) {
		p.packBinary(payload.data(), payload.size());
	}
	return RNS::Bytes(p.data(), p.size());
}

Vector<RNS::Bytes> decode_payload_list(const RNS::Bytes& data) {
	Vector<RNS::Bytes> out;
	MsgPack::Unpacker u;
	if (!(data && u.feed(data.data(), data.size()) && u.isArray())) {
		return out; // corrupted or non-array -> empty (must not crash)
	}
	size_t count = u.unpackArraySize();
	for (size_t i = 0; i < count; i++) {
		MsgPack::bin_t<uint8_t> payload;
		if (!u.deserialize(payload)) {
			continue; // skip non-bin elements defensively
		}
		out.push_back(RNS::Bytes(payload.data(), payload.size()));
	}
	return out;
}

// -- the store ---------------------------------------------------------------------------

bool Store::exists() const {
	RNS::Bytes data;
	return _io.read(CONFIG_RECORD, data);
}

/*static*/ bool Store::init(
	RecordIo& io,
	const RNS::Bytes& own_identity_hash,
	const RNS::Bytes& salt,
	int horizon_days,
	const char* rfed_topic
) {
	Store store(io);
	RNS::Bytes primarySalt = salt;
	if (!primarySalt) {
		primarySalt = RNS::Cryptography::random(SALT_SIZE);
	}
	else if (primarySalt.size() != SALT_SIZE) {
		throw std::invalid_argument(
			"Privacy Salt must be 32 bytes, got " + std::to_string(primarySalt.size())
		);
	}
	StoreConfig config;
	config.primary_salt = primarySalt;
	config.anchors.push_back(own_identity_hash);
	config.horizon_days = horizon_days;
	config.rfed_topic = rfed_topic;
	if (!store.save_config(config)) {
		return false;
	}
	if (!store.save_state(StateVector(horizon_days))) {
		return false;
	}
	if (!store.save_clock(Clock())) {
		return false;
	}
	if (!store.save_ledger(Ledger())) {
		return false;
	}
	AliasRegistry aliases;
	aliases.set_self(own_identity_hash);
	return store.save_aliases(aliases);
}

bool Store::load_config_raw(StoreConfig& config) const {
	RNS::Bytes data;
	if (!_io.read(CONFIG_RECORD, data) || !data) {
		return false;
	}
	config = decode_config_ini(data);
	return true;
}

bool Store::save_config(const StoreConfig& config) {
	const std::string ini = encode_config_ini(config);
	return _io.write(CONFIG_RECORD, RNS::Bytes(ini.data(), ini.size()), true);
}

Config Store::load_config() const {
	StoreConfig raw;
	if (!load_config_raw(raw)) {
		throw StoreError("store not initialized (run init first)");
	}
	if (raw.anchors.empty()) {
		throw StoreError("no Root Trust Anchors configured");
	}
	Set<RNS::Bytes> anchors(raw.anchors.begin(), raw.anchors.end());
	return Config(
		anchors,
		raw.primary_salt,
		raw.legacy_salts,
		{},
		raw.authoritative,
		raw.horizon_days
	);
}

Clock Store::load_clock() const {
	RNS::Bytes data;
	if (!_io.read(CLOCK_RECORD, data) || !data) {
		return Clock();
	}
	return decode_clock_payload(data);
}

bool Store::save_clock(const Clock& clock) {
	return _io.write(CLOCK_RECORD, encode_clock_payload(clock), false);
}

StateVector Store::load_state(int deletion_horizon_days) const {
	RNS::Bytes data;
	if (!_io.read(STATE_RECORD, data) || !data) {
		return StateVector(deletion_horizon_days);
	}
	// Trusted-local restore of this node's own snapshot.
	return StateVector::from_payload(data, deletion_horizon_days);
}

bool Store::save_state(const StateVector& state) {
	return _io.write(STATE_RECORD, state.to_payload(), true);
}

AliasRegistry Store::load_aliases() const {
	RNS::Bytes data;
	if (!_io.read(ALIASES_RECORD, data) || !data) {
		return AliasRegistry();
	}
	return AliasRegistry::parse(std::string((const char*)data.data(), data.size()));
}

bool Store::save_aliases(const AliasRegistry& aliases) {
	const std::string text = aliases.serialize();
	return _io.write(ALIASES_RECORD, RNS::Bytes(text.data(), text.size()), false);
}

Ledger Store::load_ledger() const {
	RNS::Bytes data;
	if (!_io.read(LEDGER_RECORD, data) || !data) {
		return Ledger();
	}
	return decode_ledger_payload(data);
}

bool Store::save_ledger(const Ledger& ledger) {
	return _io.write(LEDGER_RECORD, encode_ledger_payload(ledger), true);
}

Keyring Store::load_keyring() const {
	RNS::Bytes data;
	if (!_io.read(IDENTITIES_RECORD, data) || !data) {
		return Keyring();
	}
	return decode_keyring_payload(data);
}

bool Store::save_keyring(const Keyring& keyring) {
	return _io.write(IDENTITIES_RECORD, encode_keyring_payload(keyring), true);
}

Keyring Store::keyring_for_verify(const RNS::Bytes& own_identity_hash, const RNS::Bytes& own_sig_pub) const {
	Keyring keyring = load_keyring();
	keyring.register_single(own_identity_hash, own_sig_pub);
	return keyring;
}

Vector<RNS::Bytes> Store::load_outbox() const {
	RNS::Bytes data;
	if (!_io.read(OUTBOX_RECORD, data) || !data) {
		return {};
	}
	return decode_payload_list(data);
}

bool Store::save_outbox(const Vector<RNS::Bytes>& payloads) {
	return _io.write(OUTBOX_RECORD, encode_payload_list(payloads), true);
}

Vector<RNS::Bytes> Store::load_sent() const {
	RNS::Bytes data;
	if (!_io.read(SENT_RECORD, data) || !data) {
		return {};
	}
	return decode_payload_list(data);
}

bool Store::save_sent(const Vector<RNS::Bytes>& payloads) {
	return _io.write(SENT_RECORD, encode_payload_list(payloads), true);
}

/*static*/ bool Store::load_identity(const char* path, RNS::Identity& identity) {
	if (path == nullptr) {
		return false;
	}
	RNS::Identity loaded = RNS::Identity::from_file(path);
	if (!loaded) {
		return false;
	}
	identity = loaded;
	return true;
}

/*static*/ bool Store::save_identity(const char* path, RNS::Identity& identity) {
	if (path == nullptr) {
		return false;
	}
	if (!identity.to_file(path)) {
		return false;
	}
#if defined(DACAR_POSIX_STORE)
	// RNS writes 0644; tighten to 0600 (the private key is a secret).
	// Flash-backed filesystems have no modes (work doc #16, privacy note).
	return ::chmod(path, 0600) == 0;
#else
	return true;
#endif
}

} // namespace Dacar
