#include "stdafx.h"

#include "Crypto/ps3lock.h"
#include "Crypto/aes.h"
#include "Crypto/sha256.h"
#include "Utilities/File.h"
#include "util/logs.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <algorithm>
#include <iterator>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#endif

LOG_CHANNEL(ps3lock_log, "PS3LOCK");

// PS3LOCK: transparent whole-image decryption + offline activation (v4, RSA-OAEP).
//
// Image tag (4096 B at 0x1000, plaintext, ISO system area):
//     "PS3LCK03" | ver=3 | flags | res | recipient(16) | salt(32)
//   keystream = AES-256-CTR(K_iso, iv); the tag window keeps the keystream at 0.
//
// Activation request (274 B): "P3RQ" | ver=4 | flags | res | RSA-2048 modulus(256) | hwid(8) | crc16
// License (4452 B):          "PS3LIC04" | ver=4 | flags | res | recipient(16) | hwid(8)
//                            | RSA-OAEP(SHA256) of K_iso(32)+iv(16) = 256 B
//                            | tag copy(4096) | ECDSA-P256 signature(64)
//
// The machine key is a persisted RSA-2048 key inside a CNG provider (TPM first,
// software KSP as fallback). Persisted keys are non-exportable, so copying the
// configuration to another machine does not help: the license box cannot be opened.

namespace ps3lock
{
	// ---------------------------------------------------------------- constants
	constexpr u64 TAG_OFFSET = 0x1000;
	constexpr u64 TAG_SIZE   = 4096;

	static const u8 TAG_MAGIC[8]     = {'P','S','3','L','C','K','0','3'};
	static const u8 LICENSE_MAGIC[8] = {'P','S','3','L','I','C','0','4'};
	static const u8 REQUEST_MAGIC[4] = {'P','3','R','Q'};

	constexpr u64 REQ_VER      = 4;
	constexpr u64 LIC_VER      = 4;
	constexpr u64 RSA_BYTES    = 256;              // RSA-2048 modulus / ciphertext
	constexpr u64 BOX_PLAIN    = 48;               // K_iso(32) + iv(16)
	constexpr u64 LIC_HDR_LEN  = 8 + 4 + 16 + 8 + RSA_BYTES;   // 292
	constexpr u64 LIC_SIG_LEN  = 64;               // ECDSA P-256 raw r||s
	constexpr u64 PUB_LEN      = 65;               // issuer pubkey, uncompressed
	constexpr u64 REQ_LEN      = 4 + 4 + RSA_BYTES + 8 + 2;    // 274

	// Issuer public key (ECDSA P-256). Replace only together with keys/issuer.key.
	static const u8 ISSUER_PUB[PUB_LEN] = {
		0x04, 0x69, 0x26, 0x60, 0x08, 0xCC, 0xB4, 0x4A, 0x2E, 0x4A, 0xC1, 0x99, 0x0A, 0xCA, 0x09, 0x0F, 0xD9, 0xD7, 0xA1, 0x75, 0x7A, 0xA9, 0x40, 0x30, 0x78, 0xAD, 0x64, 0x7E, 0x20, 0xA6, 0xD8, 0x53, 0xCA, 0xA0, 0xCE, 0x84, 0x2D, 0x01, 0xA4, 0x35, 0x4B, 0x08, 0x7B, 0x7D, 0x04, 0x98, 0x61, 0xEB, 0x64, 0xDE, 0xA6, 0x8C, 0x3A, 0x56, 0xDF, 0x87, 0xBE, 0x09, 0xC9, 0x05, 0xA2, 0x2C, 0xFB, 0x84, 0x9D
	};

	// ---------------------------------------------------------------- sha256 / hmac / hkdf
	static void hash_sha256(const void* data, usz size, u8 out[32])
	{
		mbedtls_sha256_ret(static_cast<const unsigned char*>(data), size, out, 0);
	}

	static void hmac_sha256(const u8* key, usz klen, const u8* data, usz dlen, u8 out[32])
	{
		u8 k[64] = {};
		if (klen > 64)
		{
			hash_sha256(key, klen, k);
			klen = 32;
		}
		else
		{
			std::memcpy(k, key, klen);
		}

		u8 ipad[64], opad[64];
		for (int i = 0; i < 64; i++)
		{
			ipad[i] = k[i] ^ 0x36;
			opad[i] = k[i] ^ 0x5c;
		}

		u8 inner[32];
		{
			mbedtls_sha256_context ctx;
			mbedtls_sha256_init(&ctx);
			mbedtls_sha256_starts_ret(&ctx, 0);
			mbedtls_sha256_update_ret(&ctx, ipad, 64);
			mbedtls_sha256_update_ret(&ctx, data, dlen);
			mbedtls_sha256_finish_ret(&ctx, inner);
			mbedtls_sha256_free(&ctx);
		}

		mbedtls_sha256_context ctx;
		mbedtls_sha256_init(&ctx);
		mbedtls_sha256_starts_ret(&ctx, 0);
		mbedtls_sha256_update_ret(&ctx, opad, 64);
		mbedtls_sha256_update_ret(&ctx, inner, 32);
		mbedtls_sha256_finish_ret(&ctx, out);
		mbedtls_sha256_free(&ctx);
	}

	static void hkdf_sha256(const u8* ikm, usz n, const u8* salt, usz sn, const u8* info, usz in, u8* out, usz on)
	{
		u8 prk[32];
		hmac_sha256(salt, sn, ikm, n, prk);

		u8 t[32] = {};
		usz tlen = 0, done = 0;
		u8 ctr = 1;

		while (done < on)
		{
			mbedtls_sha256_context ctx;
			mbedtls_sha256_init(&ctx);
			mbedtls_sha256_starts_ret(&ctx, 0);
			mbedtls_sha256_update_ret(&ctx, t, tlen);
			mbedtls_sha256_update_ret(&ctx, info, in);
			mbedtls_sha256_update_ret(&ctx, &ctr, 1);
			mbedtls_sha256_finish_ret(&ctx, t);
			mbedtls_sha256_free(&ctx);

			tlen = 32;
			const usz take = std::min<usz>(32, on - done);
			std::memcpy(out + done, t, take);
			done += take;
			ctr++;
		}
	}

	// ---------------------------------------------------------------- image key derivation
	static void derive_iso_keys(const u8* tag, u8 k_iso[32], u8 iv[16])
	{
		static const u8 kdf_salt[9] = {'P','S','3','I','S','O','-','v','2'};
		static const u8 info_key[17] = {'P','S','3','I','S','O','-','I','S','O','-','K','E','Y','-','v','2'};
		static const u8 info_nonce[20] = {'P','S','3','I','S','O','-','B','A','S','E','-','N','O','N','C','E','-','v','2'};

		u8 km[44];
		std::memcpy(km, tag, 12);
		std::memcpy(km + 12, tag + 28, 32);

		u8 info[64];
		std::memcpy(info, info_key, sizeof(info_key));
		std::memcpy(info + sizeof(info_key), km, sizeof(km));

		hkdf_sha256(km, sizeof(km), kdf_salt, sizeof(kdf_salt), info, sizeof(info_key) + sizeof(km), k_iso, 32);

		u8 nonce0[16];
		hkdf_sha256(km, sizeof(km), kdf_salt, sizeof(kdf_salt), info_nonce, sizeof(info_nonce), nonce0, sizeof(nonce0));

		u8 km_hash[32];
		hash_sha256(km, sizeof(km), km_hash);
		for (int i = 0; i < 16; i++)
		{
			iv[i] = nonce0[i] ^ km_hash[i];
		}
	}

	// ---------------------------------------------------------------- helpers
	static u16 crc16(const u8* data, usz len)
	{
		u16 crc = 0xFFFF;
		for (usz i = 0; i < len; i++)
		{
			crc ^= data[i];
			for (int b = 0; b < 8; b++)
			{
				crc = (crc & 1) ? (u16)((crc >> 1) ^ 0xA001) : (u16)(crc >> 1);
			}
		}
		return crc;
	}

	static std::string base32(const u8* data, usz len)
	{
		static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		std::string out;
		u32 buffer = 0;
		int bits = 0;

		for (usz i = 0; i < len; i++)
		{
			buffer = (buffer << 8) | data[i];
			bits += 8;
			while (bits >= 5)
			{
				out.push_back(table[(buffer >> (bits - 5)) & 0x1F]);
				bits -= 5;
			}
		}
		if (bits > 0)
		{
			out.push_back(table[(buffer << (5 - bits)) & 0x1F]);
		}
		return out;
	}

	static std::string base32_grouped(const u8* data, usz len)
	{
		const std::string raw = base32(data, len);
		std::string out;
		for (usz i = 0; i < raw.size(); i++)
		{
			if (i && i % 4 == 0)
			{
				out.push_back('-');
			}
			out.push_back(raw[i]);
		}
		return out;
	}

	static bool read_exact(fs::file& f, u64 offset, void* buf, u64 size)
	{
		return f.read_at(offset, buf, size) == size;
	}

	static std::string config_dir()
	{
		const std::string dir = fs::get_config_dir() + "ps3lock/";
		fs::create_dir(dir);
		return dir;
	}

	static void addf(std::string& out, const char* fmt, ...)
	{
		char buf[1024];
		va_list args;
		va_start(args, fmt);
		std::vsnprintf(buf, sizeof(buf), fmt, args);
		va_end(args);
		out += buf;
	}

	static void hex_into(std::string& out, const u8* data, usz len)
	{
		for (usz i = 0; i < len; i++)
		{
			addf(out, "%02x", static_cast<unsigned>(data[i]));
		}
	}

	#ifdef _WIN32
	// Write `data` to `path` with plain Win32 (no fs::* layer) and report the error code.
	static bool write_raw_file(const std::wstring& path, const void* data, usz size, DWORD& last_error)
	{
		const HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE)
		{
			last_error = GetLastError();
			return false;
		}

		DWORD written = 0;
		const bool ok = WriteFile(h, data, static_cast<DWORD>(size), &written, nullptr) != 0 && written == size;
		last_error = ok ? 0 : GetLastError();
		CloseHandle(h);
		return ok;
	}

	static std::wstring exe_dir()
	{
		wchar_t buf[MAX_PATH * 2] = {};
		const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
		std::wstring path(buf, n);
		const auto slash = path.find_last_of(L'\\');
		return slash == std::wstring::npos ? std::wstring(L".") : path.substr(0, slash + 1);
	}

	static std::wstring env_dir(const wchar_t* var, const wchar_t* suffix)
	{
		wchar_t buf[MAX_PATH * 2] = {};
		const DWORD n = GetEnvironmentVariableW(var, buf, static_cast<DWORD>(std::size(buf)));
		if (!n || n >= std::size(buf))
		{
			return {};
		}
		std::wstring path(buf, n);
		if (!path.empty() && path.back() != L'\\') path.push_back(L'\\');
		return path + suffix;
	}

	// Candidate output directories, most natural first.
	static std::vector<std::wstring> output_dirs()
	{
		std::vector<std::wstring> dirs;
		dirs.push_back(exe_dir());
		if (auto d = env_dir(L"LOCALAPPDATA", L"rpcs3\\ps3lock\\"); !d.empty()) dirs.push_back(d);
		if (auto d = env_dir(L"TEMP", L"rpcs3-ps3lock\\"); !d.empty()) dirs.push_back(d);
		dirs.push_back(L"C:\\Windows\\Temp\\rpcs3-ps3lock\\");
		return dirs;
	}

	static std::wstring to_wide(const std::string& s)
	{
		if (s.empty()) return {};
		const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
		std::wstring w(n, L'\0');
		MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
		return w;
	}

	static std::string to_narrow(const std::wstring& w)
	{
		if (w.empty()) return {};
		const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
		std::string s(n, '\0');
		WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
		return s;
	}

	// Writes `text`/`data` to <name> somewhere writable. Returns the full path ("" on failure)
	// and appends a human readable status to `status`.
	static std::string write_output(const char* name, const void* data, usz size, std::string& status)
	{
		std::string errors;

		for (const std::wstring& dir : output_dirs())
		{
			const std::wstring path = dir + to_wide(name);

			if (dir != exe_dir())
			{
				CreateDirectoryW((dir.substr(0, dir.size() - 1)).c_str(), nullptr);
			}

			DWORD err = 0;
			if (write_raw_file(path, data, size, err))
			{
				return to_narrow(path);
			}

			errors += "\n    " + to_narrow(path) + "  (Win32 error " + std::to_string(err) + ")";
		}

		status = "could not be written to any of:" + errors;
		return {};
	}

	static void finish_report(const char* file_name, std::string text)
	{
		std::string status;
		const std::string saved_to = write_output(file_name, text.data(), text.size(), status);

		text += saved_to.empty() ? "\n[NOTE] " + std::string(file_name) + " " + status + "\n"
		                         : "\nsaved to: " + saved_to + "\n";

		std::fputs(text.c_str(), stdout);
		std::fflush(stdout);

#ifdef _WIN32
		if (!GetConsoleWindow())
		{
			MessageBoxA(nullptr, text.c_str(), "PS3LOCK", MB_ICONINFORMATION | MB_OK);
		}
#endif
	}

	#else
	static void finish_report(const char* file_name, std::string text)
	{
		std::fputs(text.c_str(), stdout);
		fs::file f(file_name, fs::write + fs::create + fs::trunc);
		if (f)
		{
			f.write(text.data(), text.size());
		}
	}
	#endif


#ifdef _WIN32
	// ---------------------------------------------------------------- CNG plumbing
	static std::string ncrypt_error_text(NTSTATUS st)
	{
		char buf[64];
		std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(st));
		return buf;
	}

	static const wchar_t* MACHINE_KEY_NAME = L"rpcs3-ps3lock-rsa";

	struct machine_key
	{
		bool valid = false;
		bool used_tpm = false;
		NCRYPT_PROV_HANDLE prov = 0;
		NCRYPT_KEY_HANDLE key = 0;
		u8 modulus[RSA_BYTES] = {};
		std::string note;   // e.g. why the TPM provider was skipped

		~machine_key()
		{
			if (key) NCryptFreeObject(key);
			if (prov) NCryptFreeObject(prov);
		}
	};

	static u32 read_u32_le(const u8* p)
	{
		return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
	}

	// Opens (or creates) the persisted RSA-2048 machine key. TPM provider first.
	static bool machine_key_open(machine_key& out, bool create, std::string& err)
	{
		const wchar_t* providers[2] = {MS_PLATFORM_KEY_STORAGE_PROVIDER, MS_KEY_STORAGE_PROVIDER};

		for (int i = 0; i < 2; i++)
		{
			if (out.prov)
			{
				NCryptFreeObject(out.prov);
				out.prov = 0;
			}
			if (out.key)
			{
				NCryptFreeObject(out.key);
				out.key = 0;
			}

			if (NCryptOpenStorageProvider(&out.prov, providers[i], 0) != ERROR_SUCCESS)
			{
				out.prov = 0;
				err = "cannot open storage provider";
				continue;
			}

			if (NCryptOpenKey(out.prov, &out.key, MACHINE_KEY_NAME, 0, 0) == ERROR_SUCCESS)
			{
				out.used_tpm = (i == 0);
				goto have_key;
			}

			out.key = 0;

			if (!create)
			{
				NCryptFreeObject(out.prov);
				out.prov = 0;
				err = "machine key not found (run --ps3lock-activate)";
				continue;
			}

			NTSTATUS st = NCryptCreatePersistedKey(out.prov, &out.key, BCRYPT_RSA_ALGORITHM, MACHINE_KEY_NAME, 0, 0);
			if (st != ERROR_SUCCESS)
			{
				out.key = 0;
				NCryptFreeObject(out.prov);
				out.prov = 0;
				err = "NCryptCreatePersistedKey failed: " + ncrypt_error_text(st) + (i == 0 ? " (TPM)" : " (software)");
				continue;
			}

			DWORD bits = 2048;
			NCryptSetProperty(out.key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);

			st = NCryptFinalizeKey(out.key, 0);
			if (st != ERROR_SUCCESS)
			{
				NCryptFreeObject(out.key);
				out.key = 0;
				NCryptFreeObject(out.prov);
				out.prov = 0;
				err = "NCryptFinalizeKey failed: " + ncrypt_error_text(st);
				continue;
			}

			out.used_tpm = (i == 0);
			goto have_key;
		}

		return false;

	have_key:
		out.note = err;   // keeps the TPM failure message when we fell back to software KSP
		std::vector<u8> blob(1024);
		DWORD need = 0;
		NTSTATUS st = NCryptExportKey(out.key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, blob.data(), static_cast<DWORD>(blob.size()), &need, 0);
		if (st != ERROR_SUCCESS)
		{
			err = "NCryptExportKey failed: " + ncrypt_error_text(st);
			return false;
		}

		blob.resize(need);

		// BCRYPT_RSAKEY_BLOB: magic, bitlen, cbPublicExp, cbModulus, cbPrime1, cbPrime2, exp[], mod[]
		if (blob.size() < 24 + 3 + RSA_BYTES)
		{
			err = "unexpected RSA public blob size";
			return false;
		}

		const u32 magic = read_u32_le(blob.data());
		const u32 cb_exp = read_u32_le(blob.data() + 8);
		const u32 cb_mod = read_u32_le(blob.data() + 12);

		if (magic != BCRYPT_RSAPUBLIC_MAGIC || cb_mod != RSA_BYTES || cb_exp != 3)
		{
			err = "unexpected RSA public blob layout";
			return false;
		}

		std::memcpy(out.modulus, blob.data() + 24 + cb_exp, RSA_BYTES);
		out.valid = true;
		return true;
	}

	static bool rsa_oaep_decrypt(machine_key& mk, const u8* in, u8* out, u32& out_len)
	{
		// OAEP with SHA-256 needs an explicit padding info, otherwise the provider
		// rejects NCRYPT_PAD_OAEP_FLAG with NTE_INVALID_PARAMETER (0x80090027).
		BCRYPT_OAEP_PADDING_INFO pad{};
		pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;

		DWORD need = BOX_PLAIN;
		NTSTATUS st = NCryptDecrypt(mk.key, const_cast<PBYTE>(in), RSA_BYTES, &pad, out, BOX_PLAIN, &need,
			NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG);

		if (st != ERROR_SUCCESS)
		{
			// Some providers refuse NCRYPT_SILENT_FLAG for persisted keys.
			need = BOX_PLAIN;
			st = NCryptDecrypt(mk.key, const_cast<PBYTE>(in), RSA_BYTES, &pad, out, BOX_PLAIN, &need, NCRYPT_PAD_OAEP_FLAG);
		}

		if (st != ERROR_SUCCESS)
		{
			ps3lock_log.error("RSA-OAEP(SHA-256) decrypt failed: %s", ncrypt_error_text(st));
			return false;
		}
		out_len = need;
		return true;
	}

	static bool ecdsa_p256_verify(const u8* hash32, const u8* sig64)
	{
		BCRYPT_ALG_HANDLE alg = nullptr;
		if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0)
		{
			return false;
		}

		BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
		u8 blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
		std::memcpy(blob, &header, sizeof(header));
		std::memcpy(blob + sizeof(header), ISSUER_PUB + 1, 64);

		BCRYPT_KEY_HANDLE key = nullptr;
		bool ok = false;
		if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, blob, sizeof(blob), 0) == 0)
		{
			ok = BCryptVerifySignature(key, nullptr, const_cast<u8*>(hash32), 32, const_cast<u8*>(sig64), 64, 0) == 0;
			BCryptDestroyKey(key);
		}
		BCryptCloseAlgorithmProvider(alg, 0);
		return ok;
	}

	static u64 hwid_hash8()
	{
		DWORD serial = 0;
		GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
		char name[MAX_COMPUTERNAME_LENGTH + 1] = {};
		DWORD name_len = sizeof(name);
		GetComputerNameA(name, &name_len);
		char buf[64];
		std::snprintf(buf, sizeof(buf), "%08lX-%s", static_cast<unsigned long>(serial), name);
		u8 digest[32];
		hash_sha256(buf, std::strlen(buf), digest);
		u64 v = 0;
		for (int i = 0; i < 8; i++) v = (v << 8) | digest[i];
		return v;
	}

	// ---------------------------------------------------------------- license
	struct license_info
	{
		bool ok = false;
		u8 recipient[16] = {};
		u8 hwid[8] = {};
		u8 box[RSA_BYTES] = {};
		std::vector<u8> tag;
		std::string error;
	};

	static std::vector<std::string> license_candidates(const std::string& image_path)
	{
		std::vector<std::string> out;
		const usz slash = image_path.find_last_of("/\\");
		if (slash != std::string::npos)
		{
			out.push_back(image_path.substr(0, slash + 1) + "license.bin");
		}
		out.push_back("license.bin");
		out.push_back(config_dir() + "license.bin");
		return out;
	}

	static license_info parse_license(const std::vector<u8>& blob)
	{
		license_info info;
		if (blob.size() != LIC_HDR_LEN + TAG_SIZE + LIC_SIG_LEN || std::memcmp(blob.data(), LICENSE_MAGIC, 8) != 0)
		{
			info.error = "not a PS3LIC04 license (or wrong size)";
			return info;
		}
		if (blob[8] != LIC_VER)
		{
			info.error = "unsupported license version";
			return info;
		}

		u8 hash[32];
		hash_sha256(blob.data(), LIC_HDR_LEN + TAG_SIZE, hash);
		if (!ecdsa_p256_verify(hash, blob.data() + LIC_HDR_LEN + TAG_SIZE))
		{
			info.error = "license signature invalid";
			return info;
		}

		std::memcpy(info.recipient, blob.data() + 12, 16);
		std::memcpy(info.hwid, blob.data() + 28, 8);
		std::memcpy(info.box, blob.data() + 36, RSA_BYTES);
		info.tag.assign(blob.begin() + LIC_HDR_LEN, blob.begin() + LIC_HDR_LEN + TAG_SIZE);
		info.ok = true;
		return info;
	}

	static bool unseal_iso_keys(const license_info& lic, machine_key& mk, u8 k_iso[32], u8 iv[16])
	{
		u8 plain[BOX_PLAIN] = {};
		u32 plain_len = 0;
		if (!rsa_oaep_decrypt(mk, lic.box, plain, plain_len) || plain_len != BOX_PLAIN)
		{
			return false;
		}

		std::memcpy(k_iso, plain, 32);
		std::memcpy(iv, plain + 32, 16);
		return true;
	}

	// ---------------------------------------------------------------- decrypting file
	class lock_file final : public fs::file_base
	{
		fs::file m_under;
		u64 m_size = 0;
		u64 m_pos = 0;
		u8 m_k_iso[32] = {};
		u8 m_iv[16] = {};

	public:
		lock_file(fs::file&& under, u64 size, const u8 k_iso[32], const u8 iv[16])
			: m_under(std::move(under))
			, m_size(size)
		{
			std::memcpy(m_k_iso, k_iso, 32);
			std::memcpy(m_iv, iv, 16);
		}

		fs::stat_t get_stat() override
		{
			fs::stat_t st = m_under.get_stat();
			st.size = m_size;
			return st;
		}

		bool trunc(u64) override { return false; }
		u64 write(const void*, u64) override { return 0; }

		u64 read(void* buffer, u64 size) override
		{
			const u64 got = read_at(m_pos, buffer, size);
			m_pos += got;
			return got;
		}

		u64 read_at(u64 offset, void* buffer, u64 size) override
		{
			if (offset >= m_size)
			{
				return 0;
			}
			size = std::min<u64>(size, m_size - offset);

			const u64 got = m_under.read_at(offset, buffer, size);
			if (!got)
			{
				return 0;
			}

			const u64 block_start = offset - (offset % 16);
			const u64 skip = offset - block_start;

			aes_context ctx;
			aes_setkey_enc(&ctx, m_k_iso, 256);

			u8 nonce_counter[16];
			std::memcpy(nonce_counter, m_iv, 16);

			u64 add = block_start / 16;
			for (int i = 15; i >= 0 && add; i--)
			{
				const u64 sum = u64(nonce_counter[i]) + (add & 0xFF);
				nonce_counter[i] = static_cast<u8>(sum & 0xFF);
				add = (add >> 8) + (sum >> 8);
			}

			const usz need = static_cast<usz>(skip + got);
			std::vector<u8> zeros(need, 0);
			std::vector<u8> keystream(need);

			usz nc_off = 0;
			u8 stream_block[16] = {};
			aes_crypt_ctr(&ctx, need, &nc_off, nonce_counter, stream_block, zeros.data(), keystream.data());

			u8* out = static_cast<u8*>(buffer);
			for (u64 i = 0; i < got; i++)
			{
				const u64 pos = offset + i;
				if (pos >= TAG_OFFSET && pos < TAG_OFFSET + TAG_SIZE)
				{
					continue; // plaintext tag window
				}
				out[i] ^= keystream[skip + i];
			}

			return got;
		}

		u64 seek(s64 offset, fs::seek_mode whence) override
		{
			s64 base = 0;
			switch (whence)
			{
			case fs::seek_set: base = 0; break;
			case fs::seek_cur: base = static_cast<s64>(m_pos); break;
			case fs::seek_end: base = static_cast<s64>(m_size); break;
			}

			const s64 target = base + offset;
			if (target < 0)
			{
				fs::g_tls_error = fs::error::inval;
				return umax;
			}

			m_pos = static_cast<u64>(target);
			return m_pos;
		}

		u64 size() override { return m_size; }

		void release() override
		{
			m_under.close();
		}
	};
#endif

	// ---------------------------------------------------------------- public API
	bool is_locked(fs::file& file)
	{
		if (!file)
		{
			return false;
		}

		u8 tag[8];
		if (!read_exact(file, TAG_OFFSET, tag, sizeof(tag)))
		{
			return false;
		}

		return std::memcmp(tag, TAG_MAGIC, sizeof(TAG_MAGIC)) == 0;
	}

	fs::file open_maybe_locked(const std::string& path, bs_t<fs::open_mode> mode)
	{
		fs::file file(path, mode);

		if (!is_locked(file))
		{
			return file;
		}

#ifdef _WIN32
		ps3lock_log.notice("Locked image detected: %s", path);

		u8 tag[TAG_SIZE];
		if (!read_exact(file, TAG_OFFSET, tag, sizeof(tag)))
		{
			ps3lock_log.error("Failed to read PS3LOCK tag from %s", path);
			return fs::file{};
		}

		license_info lic;
		for (const std::string& candidate : license_candidates(path))
		{
			fs::file lf(candidate);
			if (!lf)
			{
				continue;
			}

			std::vector<u8> blob(lf.size());
			if (lf.read(blob.data(), blob.size()) != blob.size())
			{
				continue;
			}

			lic = parse_license(blob);
			if (lic.ok)
			{
				ps3lock_log.notice("Using license %s", candidate);
				break;
			}
			ps3lock_log.error("license %s: %s", candidate, lic.error);
		}

		if (!lic.ok)
		{
			ps3lock_log.error("No valid license found (looked next to the image, the working dir and %s). "
				"Run rpcs3.exe --ps3lock-activate and send machine.req to the author.", config_dir());
			return fs::file{};
		}

		if (std::memcmp(lic.tag.data(), tag, TAG_SIZE) != 0)
		{
			ps3lock_log.error("license does not match this image (tag mismatch) — wrong license.bin?");
			return fs::file{};
		}

		machine_key mk;
		std::string err;
		if (!machine_key_open(mk, false, err))
		{
			ps3lock_log.error("Machine key unavailable: %s", err);
			return fs::file{};
		}

		u8 k_iso[32];
		u8 iv[16];
		if (!unseal_iso_keys(lic, mk, k_iso, iv))
		{
			ps3lock_log.error("Could not unseal the image key — is this license for this machine? "
				"(machine key stored in %s, provider: %s)", config_dir(), mk.used_tpm ? "TPM" : "software KSP");
			return fs::file{};
		}

		const u64 size = file.size();
		ps3lock_log.notice("License OK (recipient %02x%02x%02x%02x…, %s), decrypting on demand",
			unsigned(lic.recipient[0]), unsigned(lic.recipient[1]), unsigned(lic.recipient[2]), unsigned(lic.recipient[3]),
			mk.used_tpm ? "TPM-held RSA key" : "software-held RSA key");

		return fs::file(std::unique_ptr<fs::file_base>(new lock_file(std::move(file), size, k_iso, iv)));
#else
		ps3lock_log.error("PS3LOCK images are only supported on Windows builds");
		return fs::file{};
#endif
	}

	bool handle_command_line(int argc, char** argv)
	{
		bool do_activate = false;
		bool do_diagnose = false;

		for (int i = 1; i < argc; i++)
		{
			const std::string arg = argv[i] ? argv[i] : "";

			// Accept --ps3lock-xxx, -ps3lock-xxx, /ps3lock-xxx and bare ps3lock-xxx, any case.
			std::string key = arg;
			while (!key.empty() && (key.front() == '-' || key.front() == '/'))
			{
				key.erase(key.begin());
			}
			for (char& c : key)
			{
				if (c >= 'A' && c <= 'Z')
				{
					c = static_cast<char>(c - 'A' + 'a');
				}
			}

			if (key == "ps3lock-activate")
			{
				do_activate = true;
			}
			else if (key == "ps3lock-diagnose")
			{
				do_diagnose = true;
			}
			else if (key.find("ps3lock") != std::string::npos)
			{
				ps3lock_log.error("ps3lock: unrecognized argument '%s' (expected --ps3lock-activate or --ps3lock-diagnose)", arg);
			}
		}

		if (!do_activate && !do_diagnose)
		{
			return false;
		}

#ifdef _WIN32
		machine_key mk;
		std::string err;
		const bool have_key = machine_key_open(mk, do_activate, err);
		std::string out;

		if (do_activate)
		{
			addf(out, "=== PS3LOCK activation ===\n\n");

			if (!have_key)
			{
				addf(out, "FAILED: %s\n", err.c_str());
				finish_report("ps3lock-activate.txt", out);
				return true;
			}

			u8 request[REQ_LEN] = {};
			std::memcpy(request, REQUEST_MAGIC, 4);
			request[4] = static_cast<u8>(REQ_VER);
			std::memcpy(request + 8, mk.modulus, RSA_BYTES);

			const u64 hwid = hwid_hash8();
			for (int i = 0; i < 8; i++)
			{
				request[8 + RSA_BYTES + i] = static_cast<u8>((hwid >> ((7 - i) * 8)) & 0xFF);
			}

			const u16 crc = crc16(request, REQ_LEN - 2);
			request[REQ_LEN - 2] = static_cast<u8>(crc >> 8);
			request[REQ_LEN - 1] = static_cast<u8>(crc & 0xFF);

			std::string req_status;
			const std::string req_path = write_output("machine.req", request, sizeof(request), req_status);

			addf(out, "key provider : %s\n", mk.used_tpm ? "TPM (non-exportable)" : "software KSP (non-exportable)");
			if (!mk.used_tpm && !mk.note.empty())
			{
				addf(out, "tpm note     : %s\n", mk.note.c_str());
			}
			addf(out, "machine key  : %s\n", config_dir().c_str());
			if (req_path.empty())
			{
				addf(out, "request file : [FAILED TO WRITE] machine.req %s\n\n", req_status.c_str());
				addf(out, "Use the activation code below instead (send it as text).\n\n");
			}
			else
			{
				addf(out, "request file : %s (%u bytes)\n\n", req_path.c_str(), unsigned(sizeof(request)));
			}
			addf(out, "Send this file to the author to get license.bin.\n\n");
			addf(out, "activation code (same content, for chat):\n%s\n", base32_grouped(request, sizeof(request)).c_str());
			addf(out, "\nThis report was saved as ps3lock-activate.txt\n");

			finish_report("ps3lock-activate.txt", out);
			return true;
		}

		addf(out, "=== PS3LOCK diagnose ===\n\n");
		if (have_key)
		{
			addf(out, "machine key : present\n");
			addf(out, "provider    : %s\n", mk.used_tpm ? "TPM (non-exportable)" : "software KSP (non-exportable)");
			if (!mk.used_tpm && !mk.note.empty())
			{
				addf(out, "tpm note    : %s\n", mk.note.c_str());
			}
			addf(out, "modulus[0:16]: ");
			hex_into(out, mk.modulus, 16);
			addf(out, "\n");
		}
		else
		{
			addf(out, "machine key : MISSING (%s)\n", err.c_str());
		}
		addf(out, "config dir  : %s\n\n", config_dir().c_str());

		for (const std::string& candidate : license_candidates(""))
		{
			fs::file lf(candidate);
			if (!lf)
			{
				addf(out, "license     : %s  (not found)\n", candidate.c_str());
				continue;
			}

			std::vector<u8> blob(lf.size());
			lf.read(blob.data(), blob.size());
			const license_info lic = parse_license(blob);
			addf(out, "license     : %s  -> %s\n", candidate.c_str(), lic.ok ? "valid signature" : lic.error.c_str());
			if (lic.ok)
			{
				addf(out, "recipient   : ");
				hex_into(out, lic.recipient, 16);
				addf(out, "\n");
			}
		}

		addf(out, "\nThis report was saved as ps3lock-diagnose.txt\n");
		finish_report("ps3lock-diagnose.txt", out);
		return true;
#else
		std::printf("PS3LOCK: not supported on this platform\n");
		return true;
#endif
	}
}
