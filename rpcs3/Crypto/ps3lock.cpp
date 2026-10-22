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

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#endif

LOG_CHANNEL(ps3lock_log, "PS3LOCK");

namespace ps3lock
{
	// ---------------------------------------------------------------- constants
	constexpr u64 TAG_OFFSET = 0x1000;
	constexpr u64 TAG_SIZE   = 4096;

	static const u8 TAG_MAGIC[8]     = {'P', 'S', '3', 'L', 'C', 'K', '0', '3'};
	static const u8 LICENSE_MAGIC[8] = {'P', 'S', '3', 'L', 'I', 'C', '0', '3'};
	static const u8 REQUEST_MAGIC[4] = {'P', '3', 'R', 'Q'};

	constexpr u64 LIC_HDR_LEN = 125;   // magic(8)+ver/flags(2)+res(2)+recipient(16)+hwid(8)+eph(65)+iv(16)+box_len/res(8)
	constexpr u64 LIC_SIG_LEN = 64;    // ECDSA P-256 raw r||s
	constexpr u64 PUB_LEN     = 65;    // uncompressed P-256: 04||X||Y
	constexpr u64 PRIV_BLOB_LEN_MAX = 256;

	// Issuer public key (ECDSA P-256, uncompressed). Replace only together with keys/issuer.key.
	static const u8 ISSUER_PUB[PUB_LEN] = {
		0x04, 0x69, 0x26, 0x60, 0x08, 0xCC, 0xB4, 0x4A, 0x2E, 0x4A, 0xC1, 0x99, 0x0A, 0xCA, 0x09, 0x0F, 0xD9, 0xD7, 0xA1, 0x75, 0x7A, 0xA9, 0x40, 0x30, 0x78, 0xAD, 0x64, 0x7E, 0x20, 0xA6, 0xD8, 0x53, 0xCA, 0xA0, 0xCE, 0x84, 0x2D, 0x01, 0xA4, 0x35, 0x4B, 0x08, 0x7B, 0x7D, 0x04, 0x98, 0x61, 0xEB, 0x64, 0xDE, 0xA6, 0x8C, 0x3A, 0x56, 0xDF, 0x87, 0xBE, 0x09, 0xC9, 0x05, 0xA2, 0x2C, 0xFB, 0x84, 0x9D };

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

	// HKDF-SHA256 (extract + expand)
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

	// ---------------------------------------------------------------- tag math (mirror of tools/iso_pack.py)
	static void derive_iso_keys(const u8* tag, u8 k_iso[32], u8 iv[16])
	{
		static const u8 kdf_salt[10] = {'P','S','3','I','S','O','-','v','2', 0}; // b"PS3ISO-v2" (9 chars, NUL kept for length)
		static const u8 info_key[18] = {'P','S','3','I','S','O','-','I','S','O','-','K','E','Y','-','v','2', 0};
		static const u8 info_nonce[20] = {'P','S','3','I','S','O','-','B','A','S','E','-','N','O','N','C','E','-','v','2'};

		const usz salt_len = 9;   // strlen("PS3ISO-v2")
		const usz info_key_len = 17;

		u8 km[44];
		std::memcpy(km, tag, 12);
		std::memcpy(km + 12, tag + 28, 32);

		u8 info[64];
		std::memcpy(info, info_key, info_key_len);
		std::memcpy(info + info_key_len, km, sizeof(km));

		hkdf_sha256(km, sizeof(km), kdf_salt, salt_len, info, info_key_len + sizeof(km), k_iso, 32);

		u8 nonce0[16];
		hkdf_sha256(km, sizeof(km), kdf_salt, salt_len, info_nonce, sizeof(info_nonce), nonce0, sizeof(nonce0));

		u8 km_hash[32];
		hash_sha256(km, sizeof(km), km_hash);
		for (int i = 0; i < 16; i++)
		{
			iv[i] = nonce0[i] ^ km_hash[i];
		}
	}

	// ---------------------------------------------------------------- misc helpers
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

	static bool read_exact(const fs::file& f, u64 offset, void* buf, u64 size)
	{
		return f.read_at(offset, buf, size) == size;
	}

	static std::string config_dir()
	{
		const std::string dir = fs::get_config_dir() + "ps3lock/";
		fs::create_dir(dir);
		return dir;
	}

#ifdef _WIN32
	// ---------------------------------------------------------------- windows crypto plumbing
	static std::string ncrypt_error_text(NTSTATUS st)
	{
		char buf[64];
		std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(st));
		return buf;
	}

	struct machine_key
	{
		bool valid = false;
		bool used_tpm = false;
		std::vector<u8> priv_blob;   // BCRYPT_ECCPRIVATE_BLOB (P-256)
		u8 pub[PUB_LEN] = {};        // uncompressed
	};

	// Returns both handles: free the key first, then the provider (child before parent).
	static bool tpm_open_wrapping_key(NCRYPT_PROV_HANDLE& prov, NCRYPT_KEY_HANDLE& out_key, bool& created)
	{
		created = false;
		prov = 0;
		out_key = 0;

		if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
		{
			prov = 0;
			return false;
		}

		if (NCryptOpenKey(prov, &out_key, L"rpcs3-ps3lock-wk", 0, 0) == ERROR_SUCCESS)
		{
			return true;
		}

		if (NCryptCreatePersistedKey(prov, &out_key, BCRYPT_RSA_ALGORITHM, L"rpcs3-ps3lock-wk", 0, 0) != ERROR_SUCCESS)
		{
			NCryptFreeObject(prov);
			prov = 0;
			out_key = 0;
			return false;
		}

		DWORD bits = 2048;
		NCryptSetProperty(out_key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);

		if (NCryptFinalizeKey(out_key, 0) != ERROR_SUCCESS)
		{
			NCryptFreeObject(out_key);
			NCryptFreeObject(prov);
			prov = 0;
			out_key = 0;
			return false;
		}

		created = true;
		return true;
	}

	// Wrap/unwrap the small private blob: TPM (OAEP) first, DPAPI fallback.
	static bool wrap_blob(const std::vector<u8>& in, u8& kind, std::vector<u8>& out)
	{
		NCRYPT_PROV_HANDLE prov = 0;
		NCRYPT_KEY_HANDLE key = 0;
		bool created = false;
		if (tpm_open_wrapping_key(prov, key, created))
		{
			DWORD need = 0;
			bool done = false;
			if (NCryptEncrypt(key, const_cast<PBYTE>(in.data()), static_cast<DWORD>(in.size()), nullptr, nullptr, 0, &need, NCRYPT_PAD_OAEP_FLAG) == ERROR_SUCCESS)
			{
				out.resize(need);
				if (NCryptEncrypt(key, const_cast<PBYTE>(in.data()), static_cast<DWORD>(in.size()), nullptr, out.data(), need, &need, NCRYPT_PAD_OAEP_FLAG) == ERROR_SUCCESS)
				{
					out.resize(need);
					kind = 1;
					done = true;
				}
			}
			NCryptFreeObject(key);
			NCryptFreeObject(prov);
			if (done)
			{
				return true;
			}
		}

		DATA_BLOB din{static_cast<DWORD>(in.size()), const_cast<BYTE*>(in.data())};
		DATA_BLOB dout{};
		if (CryptProtectData(&din, L"ps3lock", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &dout))
		{
			out.assign(dout.pbData, dout.pbData + dout.cbData);
			LocalFree(dout.pbData);
			kind = 2;
			return true;
		}
		return false;
	}

	static bool unwrap_blob(u8 kind, const std::vector<u8>& in, std::vector<u8>& out)
	{
		if (kind == 1)
		{
			NCRYPT_PROV_HANDLE prov = 0;
			NCRYPT_KEY_HANDLE key = 0;
			bool created = false;
			if (!tpm_open_wrapping_key(prov, key, created))
			{
				return false;
			}

			DWORD need = 0;
			NTSTATUS st = NCryptDecrypt(key, const_cast<PBYTE>(in.data()), static_cast<DWORD>(in.size()), nullptr, nullptr, 0, &need, NCRYPT_PAD_OAEP_FLAG);
			if (st != ERROR_SUCCESS)
			{
				NCryptFreeObject(key);
				NCryptFreeObject(prov);
				ps3lock_log.error("TPM unwrap failed: %s", ncrypt_error_text(st));
				return false;
			}

			out.resize(need);
			st = NCryptDecrypt(key, const_cast<PBYTE>(in.data()), static_cast<DWORD>(in.size()), nullptr, out.data(), need, &need, NCRYPT_PAD_OAEP_FLAG);
			NCryptFreeObject(key);
			NCryptFreeObject(prov);
			if (st != ERROR_SUCCESS)
			{
				return false;
			}
			out.resize(need);
			return true;
		}

		if (kind == 2)
		{
			DATA_BLOB din{static_cast<DWORD>(in.size()), const_cast<BYTE*>(in.data())};
			DATA_BLOB dout{};
			if (!CryptUnprotectData(&din, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &dout))
			{
				return false;
			}
			out.assign(dout.pbData, dout.pbData + dout.cbData);
			LocalFree(dout.pbData);
			return true;
		}
		return false;
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

	static bool ecdh_p256_raw(const std::vector<u8>& priv_blob, const u8* peer_uncompressed, u8 out[32])
	{
		BCRYPT_ALG_HANDLE alg = nullptr;
		if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0) != 0)
		{
			return false;
		}

		BCRYPT_KEY_HANDLE priv = nullptr;
		BCRYPT_KEY_HANDLE pub = nullptr;
		BCRYPT_SECRET_HANDLE secret = nullptr;
		bool ok = false;

		if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &priv,
			const_cast<u8*>(priv_blob.data()), static_cast<ULONG>(priv_blob.size()), 0) == 0)
		{
			BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDH_PUBLIC_P256_MAGIC, 32};
			u8 blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
			std::memcpy(blob, &header, sizeof(header));
			std::memcpy(blob + sizeof(header), peer_uncompressed + 1, 64);

			if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &pub, blob, sizeof(blob), 0) == 0)
			{
				if (BCryptSecretAgreement(priv, pub, &secret, 0) == 0)
				{
					ULONG cb = 0;
					// RAW_SECRET: the shared secret is used directly as key material (x-coordinate).
					if (BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET, nullptr, out, 32, &cb, 0) != 0 || cb != 32)
					{
						cb = 0;
						ok = (BCryptDeriveKey(secret, nullptr, nullptr, out, 32, &cb, 0) == 0 && cb == 32);
					}
					else
					{
						ok = true;
					}
					BCryptDestroySecret(secret);
				}
			}
		}

		if (pub) BCryptDestroyKey(pub);
		if (priv) BCryptDestroyKey(priv);
		BCryptCloseAlgorithmProvider(alg, 0);
		return ok;
	}

	static bool generate_machine_key(machine_key& out)
	{
		BCRYPT_ALG_HANDLE alg = nullptr;
		if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0) != 0)
		{
			return false;
		}

		BCRYPT_KEY_HANDLE key = nullptr;
		bool ok = false;
		if (BCryptGenerateKeyPair(alg, &key, 256, 0) == 0 && BCryptFinalizeKeyPair(key, 0) == 0)
		{
			ULONG need = 0;
			if (BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &need, 0) == 0 && need && need <= PRIV_BLOB_LEN_MAX)
			{
				out.priv_blob.resize(need);
				if (BCryptExportKey(key, nullptr, BCRYPT_ECCPRIVATE_BLOB, out.priv_blob.data(), need, &need, 0) == 0)
				{
					out.priv_blob.resize(need);
					ok = true;
				}
			}
		}
		if (key) BCryptDestroyKey(key);
		BCryptCloseAlgorithmProvider(alg, 0);
		return ok;
	}

	static bool machine_pub_from_priv(const std::vector<u8>& priv_blob, u8 out[PUB_LEN])
	{
		// BCRYPT_ECCPRIVATE_BLOB layout: header(8) + X(32) + Y(32) + d(32)
		if (priv_blob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 96)
		{
			return false;
		}
		out[0] = 0x04;
		std::memcpy(out + 1, priv_blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), 64);
		return true;
	}

	static bool compress_pub(const u8* pub65, u8 out33[33])
	{
		out33[0] = (pub65[64] & 1) ? 0x03 : 0x02;
		std::memcpy(out33 + 1, pub65 + 1, 32);
		return true;
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

	// ---------------------------------------------------------------- machine key file
	static std::string machine_key_path()
	{
		return config_dir() + "machine.key";
	}

	static bool save_machine_key(const machine_key& key)
	{
		u8 kind = 0;
		std::vector<u8> wrapped;
		if (!wrap_blob(key.priv_blob, kind, wrapped))
		{
			ps3lock_log.error("Failed to wrap machine key (TPM + DPAPI both failed)");
			return false;
		}

		std::vector<u8> blob;
		static const u8 key_magic[8] = {'P','S','3','L','K','K','E','Y'};
		blob.insert(blob.end(), key_magic, key_magic + 8);
		blob.push_back(1);           // version
		blob.push_back(kind);        // 1 = TPM RSA-OAEP, 2 = DPAPI
		blob.insert(blob.end(), key.pub, key.pub + PUB_LEN);
		const u32 len = static_cast<u32>(wrapped.size());
		for (int i = 3; i >= 0; i--) blob.push_back(static_cast<u8>((len >> (i * 8)) & 0xFF));
		blob.insert(blob.end(), wrapped.begin(), wrapped.end());

		fs::file f(machine_key_path(), fs::write + fs::create + fs::trunc);
		if (!f)
		{
			ps3lock_log.error("Failed to write %s", machine_key_path());
			return false;
		}
		f.write(blob.data(), blob.size());
		return true;
	}

	static bool load_machine_key(machine_key& out, bool create_if_missing)
	{
		const std::string path = machine_key_path();
		fs::file f(path);

		if (!f)
		{
			if (!create_if_missing)
			{
				return false;
			}

			machine_key fresh;
			if (!generate_machine_key(fresh) || !machine_pub_from_priv(fresh.priv_blob, fresh.pub))
			{
				ps3lock_log.error("Failed to generate machine key");
				return false;
			}

			if (!save_machine_key(fresh))
			{
				return false;
			}

			fresh.valid = true;
			out = fresh;
			ps3lock_log.notice("Created new machine key (%s)", path);
			return true;
		}

		const u64 size = f.size();
		if (size < 8 + 2 + PUB_LEN + 4 || size > 4096)
		{
			return false;
		}

		std::vector<u8> blob(size);
		if (f.read(blob.data(), size) != size || std::memcmp(blob.data(), "PS3LKKEY", 8) != 0)
		{
			return false;
		}

		const u8 kind = blob[9];
		std::memcpy(out.pub, blob.data() + 10, PUB_LEN);
		const u32 wlen = (u32(blob[75]) << 24) | (u32(blob[76]) << 16) | (u32(blob[77]) << 8) | u32(blob[78]);

		if (79 + wlen > blob.size())
		{
			return false;
		}

		std::vector<u8> wrapped(blob.begin() + 79, blob.begin() + 79 + wlen);
		if (!unwrap_blob(kind, wrapped, out.priv_blob))
		{
			ps3lock_log.error("Failed to unwrap machine key (kind=%u) — was it copied from another machine?", kind);
			return false;
		}

		out.used_tpm = (kind == 1);
		out.valid = true;
		return true;
	}

	// ---------------------------------------------------------------- license
	struct license_info
	{
		bool ok = false;
		u8 recipient[16] = {};
		u8 hwid[8] = {};
		u8 eph[PUB_LEN] = {};
		u8 iv[16] = {};
		std::vector<u8> box;
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
		out.push_back(config_dir() + "license.bin");
		return out;
	}

	static license_info parse_license(const std::vector<u8>& blob)
	{
		license_info info;
		if (blob.size() < LIC_HDR_LEN + TAG_SIZE + LIC_SIG_LEN || std::memcmp(blob.data(), LICENSE_MAGIC, 8) != 0)
		{
			info.error = "not a PS3LIC03 license";
			return info;
		}
		if (blob[8] != 3)
		{
			info.error = "unsupported license version";
			return info;
		}

		const usz body_len = blob.size() - LIC_SIG_LEN;

		u8 hash[32];
		hash_sha256(blob.data(), body_len, hash);
		if (!ecdsa_p256_verify(hash, blob.data() + body_len))
		{
			info.error = "license signature invalid";
			return info;
		}

		std::memcpy(info.recipient, blob.data() + 12, 16);
		std::memcpy(info.hwid, blob.data() + 28, 8);
		std::memcpy(info.eph, blob.data() + 36, PUB_LEN);
		std::memcpy(info.iv, blob.data() + 101, 16);
		const u32 box_len = (u32(blob[117]) << 24) | (u32(blob[118]) << 16) | (u32(blob[119]) << 8) | u32(blob[120]);

		if (LIC_HDR_LEN + box_len + TAG_SIZE != body_len)
		{
			info.error = "license layout mismatch";
			return info;
		}

		info.box.assign(blob.begin() + LIC_HDR_LEN, blob.begin() + LIC_HDR_LEN + box_len);
		info.tag.assign(blob.begin() + LIC_HDR_LEN + box_len, blob.begin() + LIC_HDR_LEN + box_len + TAG_SIZE);
		info.ok = true;
		return info;
	}

	static bool unseal_iso_keys(const license_info& lic, const machine_key& mk, u8 k_iso[32], u8 iv[16])
	{
		if (lic.box.size() != 32 + 16 + 32)
		{
			ps3lock_log.error("license box has unexpected size %u", static_cast<unsigned>(lic.box.size()));
			return false;
		}

		u8 shared[32];
		if (!ecdh_p256_raw(mk.priv_blob, lic.eph, shared))
		{
			ps3lock_log.error("ECDH failed");
			return false;
		}

		static const u8 kdf_salt[9] = {'P','S','3','L','I','C','-','v','3'};
		static const u8 kdf_info[13] = {'P','S','3','L','I','C','-','B','O','X','-','v','3'};
		u8 k[64];
		hkdf_sha256(shared, 32, kdf_salt, 9, kdf_info, 13, k, sizeof(k));

		const u8* k_enc = k;
		const u8* k_mac = k + 32;
		const u8* ct = lic.box.data();
		const usz ct_len = lic.box.size() - 32;
		const u8* mac = lic.box.data() + ct_len;

		u8 mac_input[16 + 128];
		std::memcpy(mac_input, lic.iv, 16);
		std::memcpy(mac_input + 16, ct, ct_len);

		u8 want[32];
		hmac_sha256(k_mac, 32, mac_input, 16 + ct_len, want);

		if (std::memcmp(want, mac, 32) != 0)
		{
			ps3lock_log.error("license box MAC mismatch — license is not for this machine");
			return false;
		}

		aes_context ctx;
		aes_setkey_enc(&ctx, k_enc, 256);
		u8 plain[48];
		usz nc_off = 0;
		u8 nonce_counter[16];
		u8 stream_block[16] = {};
		std::memcpy(nonce_counter, lic.iv, 16);
		aes_crypt_ctr(&ctx, ct_len, &nc_off, nonce_counter, stream_block, ct, plain);

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

			// Keystream is offset based (AES-256-CTR, 128-bit BE counter starting at iv);
			// the tag window [0x1000, 0x2000) stays plaintext.
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
#else
	struct license_info { bool ok = false; std::string error; };
	struct machine_key { bool valid = false; bool used_tpm = false; std::vector<u8> priv_blob; u8 pub[PUB_LEN] = {}; };
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
				break;
			}
			ps3lock_log.error("license %s: %s", candidate, lic.error);
		}

		if (!lic.ok)
		{
			ps3lock_log.error("No valid license found for %s (looked next to the image and in the config dir). "
				"Run: rpcs3 --ps3lock-activate", path);
			return fs::file{};
		}

		if (std::memcmp(lic.tag.data(), tag, TAG_SIZE) != 0)
		{
			ps3lock_log.error("license does not match this image (tag mismatch) — wrong license.bin?");
			return fs::file{};
		}

		machine_key mk;
		if (!load_machine_key(mk, false))
		{
			ps3lock_log.error("Machine key missing/invalid. Run: rpcs3 --ps3lock-activate");
			return fs::file{};
		}

		u8 k_iso[32];
		u8 iv[16];
		if (!unseal_iso_keys(lic, mk, k_iso, iv))
		{
			return fs::file{};
		}

		const u64 size = file.size();
		ps3lock_log.notice("License OK (recipient %02x%02x%02x%02x…, %s), decrypting on demand",
			lic.recipient[0], lic.recipient[1], lic.recipient[2], lic.recipient[3],
			mk.used_tpm ? "TPM-wrapped key" : "DPAPI-wrapped key");

		return fs::file(std::unique_ptr<fs::file_base>(new lock_file(std::move(file), size, k_iso, iv)));
#else
		ps3lock_log.error("PS3LOCK images are only supported on Windows builds");
		return fs::file{};
#endif
	}

	// Small printf-style append helper (no fmt dependency here).
	static void addf(std::string& out, const char* fmt, ...)
	{
		char buf[1024];
		va_list args;
		va_start(args, fmt);
		std::vsnprintf(buf, sizeof(buf), fmt, args);
		va_end(args);
		out += buf;
	}

	// Write the report to stdout, to a file next to the working dir, and show a
	// message box when launched without a console (double click).
	static void finish_report(const char* file_name, const std::string& text)
	{
		std::fputs(text.c_str(), stdout);
		std::fflush(stdout);

		fs::file f(file_name, fs::write + fs::create + fs::trunc);
		if (f)
		{
			f.write(text.data(), text.size());
		}

#ifdef _WIN32
		if (!GetConsoleWindow())
		{
			MessageBoxA(nullptr, text.c_str(), "PS3LOCK", MB_ICONINFORMATION | MB_OK);
		}
#endif
	}

	bool handle_command_line(int argc, char** argv)
	{
		bool do_activate = false;
		bool do_diagnose = false;

		for (int i = 1; i < argc; i++)
		{
			const std::string arg = argv[i] ? argv[i] : "";
			if (arg == "--ps3lock-activate") do_activate = true;
			else if (arg == "--ps3lock-diagnose") do_diagnose = true;
		}

		if (!do_activate && !do_diagnose)
		{
			return false;
		}

#ifdef _WIN32
		machine_key mk;
		const bool have_key = load_machine_key(mk, do_activate);
		std::string out;

		if (do_activate)
		{
			addf(out, "=== PS3LOCK activation ===\n\n");

			if (!have_key)
			{
				addf(out, "FAILED: could not create or load the machine key.\n");
				addf(out, "        config dir: %s\n", config_dir().c_str());
				finish_report("ps3lock-activate.txt", out);
				return true;
			}

			u8 compressed[33];
			compress_pub(mk.pub, compressed);

			u8 request[51];
			std::memcpy(request, REQUEST_MAGIC, 4);
			request[4] = 3;
			request[5] = 0;
			request[6] = 0;
			request[7] = 0;
			std::memcpy(request + 8, compressed, 33);

			const u64 hwid = hwid_hash8();
			for (int i = 0; i < 8; i++)
			{
				request[41 + i] = static_cast<u8>((hwid >> ((7 - i) * 8)) & 0xFF);
			}

			const u16 crc = crc16(request, 49);
			request[49] = static_cast<u8>(crc >> 8);
			request[50] = static_cast<u8>(crc & 0xFF);

			const std::string path = "machine.req";
			fs::file f(path, fs::write + fs::create + fs::trunc);
			const bool written = f && f.write(request, sizeof(request)) == sizeof(request);

			addf(out, "key wrapping : %s\n", mk.used_tpm ? "TPM (non-exportable RSA)" : "DPAPI (software)");
			addf(out, "machine key  : %s\n", config_dir().c_str());
			addf(out, "\nrequest file : %s%s (%u bytes)\n",
				path.c_str(), written ? "" : "  [FAILED TO WRITE]", static_cast<unsigned>(sizeof(request)));
			addf(out, "send this file to the author.\n\n");
			addf(out, "activation code (same content, for chat):\n%s\n", base32_grouped(request, sizeof(request)).c_str());
			addf(out, "\nThis file is saved as ps3lock-activate.txt in the current folder.\n");

			finish_report("ps3lock-activate.txt", out);
			return true;
		}

		addf(out, "=== PS3LOCK diagnose ===\n\n");
		addf(out, "machine key : %s\n", have_key ? "present" : "MISSING (run --ps3lock-activate)");
		if (have_key)
		{
			addf(out, "wrapping    : %s\n", mk.used_tpm ? "TPM (non-exportable RSA)" : "DPAPI (software)");
			addf(out, "machine.pub : ");
			for (u8 b : mk.pub) addf(out, "%02x", static_cast<unsigned>(b));
			addf(out, "\n");
		}
		addf(out, "config dir  : %s\n\n", config_dir().c_str());

		const std::string config_license = config_dir() + "license.bin";
		const std::string candidates[2] = {"license.bin", config_license};

		for (const std::string& candidate : candidates)
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
				for (u8 b : lic.recipient) addf(out, "%02x", static_cast<unsigned>(b));
				addf(out, "\n");
			}
		}
		addf(out, "\nThis file is saved as ps3lock-diagnose.txt in the current folder.\n");

		finish_report("ps3lock-diagnose.txt", out);
		return true;
#else
		std::printf("PS3LOCK: not supported on this platform\n");
		return true;
#endif
	}
}
