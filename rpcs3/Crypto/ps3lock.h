#pragma once

// PS3LOCK: transparent whole-image decryption for locked .iso images + offline activation.
//
// Format (all big-endian), see 知识库/13-防破解与追溯方案.md §9:
//   tag (4096 B at image offset 0x1000, plaintext): "PS3LCK03" | ver=3 | flags | res | recipient(16) | salt(32)
//   stream = AES-256-CTR(K_iso, iv), keystream forced to 0 inside [0x1000, 0x2000)
//   license.bin: "PS3LIC03" | ... | box(ct||hmac32) | tag copy | ECDSA-P256 signature
//   machine key: P-256 ECDH keypair, private part wrapped by a TPM-held RSA key (fallback: DPAPI)
//
// This file is Windows-only in practice; other platforms compile stubs (no decryption).

#include <string>

#include "Utilities/File.h"

namespace ps3lock
{
	// Returns true if the file carries the PS3LOCK tag (checked at 0x1000). Takes a mutable ref (read_at is non-const).
	bool is_locked(fs::file& file);

	// Opens `path`. If the image is locked, returns a decrypting wrapper
	// (invalid file + log error when the license is missing/invalid).
	fs::file open_maybe_locked(const std::string& path, bs_t<fs::open_mode> mode);

	// Handles --ps3lock-activate / --ps3lock-diagnose. Returns true when handled.
	bool handle_command_line(int argc, char** argv);
}
