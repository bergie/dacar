/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * microStore record backend for MCU targets (work doc #16 Phase 2).
 *
 * Holds the §13 logical records in microStore's Bitcask-style FileStore:
 * one key per record, values byte-identical to the §13 loose-file layout.
 * The spec (§13) permits alternative persistence backends when logical
 * records and semantics are preserved, which this backend does — only the
 * physical representation changes (append-only segments + compaction rather
 * than loose files), fitting flash-backed filesystems where loose-file churn
 * is costly. File modes do not exist on flash (work doc #16: §13.1 modes
 * only apply to the POSIX backend).
 *
 * The store (BasicFileStore) is owned by the firmware and initialized with
 * the filesystem + segment sizing appropriate for the board; e.g. on the
 * nRF52840's 28 KB internal FS use small segments:
 *
 *   microStore::Adapters::InternalFSFileSystem fs;
 *   Dacar::MicroStoreRecordIo::BlobStore store(4096, 2);
 *   store.init(fs, "/dacar");
 *   Dacar::MicroStoreRecordIo io(store);
 *
 * Note: USTORE_MAX_VALUE_LEN (default 1024) bounds record size — build the
 * whole firmware with a raised limit (e.g. 16384) so Dacar state/outbox
 * records fit, and keep it consistent across a fleet (a smaller limit on
 * load drops larger records as corrupt).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Store.h"

#include <microStore/FileStore.h>

#include <cstring>
#include <vector>

namespace Dacar {

	class MicroStoreRecordIo : public RecordIo {

	public:
		using BlobStore = microStore::BasicFileStore<ContainerAllocator<uint8_t>>;

		// `store` must be initialized (store.init(filesystem, prefix, ...))
		// before use; the prefix namespaces Dacar's records.
		explicit MicroStoreRecordIo(BlobStore& store)
			: _store(store)
		{}
		~MicroStoreRecordIo() = default;

		bool read(const char* name, RNS::Bytes& data) override {
			const std::vector<uint8_t> key(name, name + std::strlen(name));
			std::vector<uint8_t> raw;
			if (!_store.get(key, raw)) {
				return false;
			}
			data = RNS::Bytes(raw.data(), raw.size());
			return true;
		}

		bool write(const char* name, const RNS::Bytes& data, bool secret) override {
			(void)secret; // no file modes on flash (§13.1 note)
			const std::vector<uint8_t> key(name, name + std::strlen(name));
			std::vector<uint8_t> value;
			if (data.size()) {
				value.assign(data.data(), data.data() + data.size());
			}
			return _store.put(key, value);
		}

	private:
		BlobStore& _store;

	};

} // namespace Dacar
