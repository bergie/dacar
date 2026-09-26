/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * §13 loose-file record backend over a POSIX directory (native targets).
 *
 * Writes the exact reference store layout: one loose file per record at the
 * directory root, with the §13.1 modes (0700 directory; 0600 secret records;
 * 0644 public records) set explicitly, independent of umask. Files produced
 * here are byte-identical to the canonical Python / JS stores, so a store
 * directory moves between implementations interchangeably (§13.11).
 *
 * Compiled only where DACAR_POSIX_STORE is defined (the CMake native build
 * and the PlatformIO `native` envs define it; embedded builds use
 * MicroStoreIo instead).
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#pragma once

#include "Store.h"

#include <string>

#if defined(DACAR_POSIX_STORE)

namespace Dacar {

	class PosixRecordIo : public RecordIo {

	public:
		// `dir`: the store directory (e.g. ~/.dacar). It is created (with
		// mode 0700, parents as needed) by ensure_directory(); reads and
		// writes work relative to it.
		explicit PosixRecordIo(const char* dir)
			: _dir(dir)
		{}
		~PosixRecordIo() = default;

		const std::string& dir() const { return _dir; }

		// Create the store directory (mode 0700) including parents.
		// Returns true when it exists afterwards.
		bool ensure_directory() const;

		// Remove every known store record (test helper); the directory
		// itself and foreign files are left alone.
		bool remove_records() const;

		bool read(const char* name, RNS::Bytes& data) override;
		bool write(const char* name, const RNS::Bytes& data, bool secret) override;
		const char* path_for(const char* name) const override;

	private:
		std::string _dir;
		mutable std::string _path_buf;

	};

} // namespace Dacar

#endif // DACAR_POSIX_STORE
