/*
 * Dacar: Decentralized Access Control for Reticulum.
 *
 * Licensed under the EUPL-1.2 (see repository root).
 */

#include "PosixStore.h"

#if defined(DACAR_POSIX_STORE)

#include "microReticulum/Log.h"

#include <cstdio>
#include <cerrno>
#include <cstring>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

using namespace Dacar;

namespace {

	// mkdir -p with 0700 (the §13.1 store-directory mode).
	bool makeDirectories(const std::string& path) {
		if (path.empty()) {
			return false;
		}
		std::string partial;
		partial.reserve(path.size());
		size_t pos = 0;
		if (path[0] == '/') {
			partial = "/";
			pos = 1;
		}
		while (pos <= path.size()) {
			size_t sep = path.find('/', pos);
			std::string component = path.substr(pos, sep == std::string::npos ? std::string::npos : sep - pos);
			pos = (sep == std::string::npos) ? path.size() + 1 : sep + 1;
			if (component.empty()) {
				continue;
			}
			if (!partial.empty() && partial.back() != '/') {
				partial += "/";
			}
			partial += component;
			if (::mkdir(partial.c_str(), 0700) != 0 && errno != EEXIST) {
				return false;
			}
		}
		struct stat st;
		if (::stat(path.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
			return false;
		}
		return true;
	}

	bool fileExists(const std::string& path) {
		struct stat st;
		return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
	}

} // namespace

bool PosixRecordIo::ensure_directory() const {
	return makeDirectories(_dir);
}

bool PosixRecordIo::remove_records() const {
	static const char* records[] = {
		CONFIG_RECORD, CLOCK_RECORD, STATE_RECORD, ALIASES_RECORD,
		LEDGER_RECORD, IDENTITIES_RECORD, OUTBOX_RECORD, SENT_RECORD,
		IDENTITY_RECORD,
	};
	bool ok = true;
	for (const char* record : records) {
		const std::string path = _dir + "/" + record;
		if (fileExists(path) && ::unlink(path.c_str()) != 0) {
			ok = false;
		}
	}
	return ok;
}

bool PosixRecordIo::read(const char* name, RNS::Bytes& data) {
	const std::string path = _dir + "/" + name;
	FILE* fh = std::fopen(path.c_str(), "rb");
	if (fh == nullptr) {
		return false;
	}
	bool ok = false;
	if (std::fseek(fh, 0, SEEK_END) == 0) {
		long size = std::ftell(fh);
		if (size >= 0 && std::fseek(fh, 0, SEEK_SET) == 0) {
			data.resize((size_t)size);
			size_t got = size ? std::fread(data.writable((size_t)size), 1, (size_t)size, fh) : 0;
			if (got == (size_t)size) {
				ok = true;
			}
		}
	}
	std::fclose(fh);
	return ok;
}

bool PosixRecordIo::write(const char* name, const RNS::Bytes& data, bool secret) {
	const std::string path = _dir + "/" + name;
	FILE* fh = std::fopen(path.c_str(), "wb");
	if (fh == nullptr) {
		return false;
	}
	size_t put = data.size() ? std::fwrite(data.data(), 1, data.size(), fh) : 0;
	std::fclose(fh);
	if (put != data.size()) {
		return false;
	}
	// Explicit modes independent of umask (§13.1).
	mode_t mode = secret ? 0600 : 0644;
	if (::chmod(path.c_str(), mode) != 0) {
		return false;
	}
	return true;
}

const char* PosixRecordIo::path_for(const char* name) const {
	_path_buf = _dir + "/" + name;
	return _path_buf.c_str();
}

#endif // DACAR_POSIX_STORE
