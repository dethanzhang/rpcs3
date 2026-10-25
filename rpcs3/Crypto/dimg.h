#pragma once

// Transparent whole-image decryption for locked .iso images + offline activation.
//
// Format (all big-endian, v4):
//   tag (4096 B at image offset 0x1000): "PS3LCK03" | ver=3 | flags | res | recipient(16) | salt(32)
//   stream = AES-256-CTR(K_iso, iv), keystream forced to 0 inside [0x1000, 0x2000)
//   request.bin: "P3RQ" | ver=4 | flags | res | RSA-2048 modulus(256) | hwid(8) | crc16 | ("P3RX" bundle)
//   license.bin: "PS3LIC04" | ver=4 | flags | res | recipient(16) | hwid(8)
//                | RSA-OAEP(SHA-256) of K_iso(32)+iv(16) = 256 B | tag copy(4096) | ECDSA-P256 sig(64)
//   machine key: persisted, non-exportable RSA-2048 in a CNG provider (TPM first, software KSP fallback)
//
// The on-disk magics are kept for compatibility; in the binary they are XOR-masked (see MAGIC_XOR).
// This file is Windows-only in practice; other platforms compile stubs (no decryption).

#include <string>

#include "Utilities/File.h"

namespace dimg
{
	// Returns true if the file carries the image tag (checked at 0x1000). Takes a mutable ref (read_at is non-const).
	bool is_locked(fs::file& file);

	// Opens `path`. If the image is locked, returns a decrypting wrapper
	// (invalid file + log error when the activation data is missing/invalid).
	fs::file open_maybe_locked(const std::string& path, bs_t<fs::open_mode> mode);

	// Handles --activate / --diag / --reset-key. Returns true when handled.
	bool handle_command_line(int argc, char** argv);
}
