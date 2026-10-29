#include "stdafx.h"

#include "Crypto/dimg.h"
#include "Crypto/aes.h"
#include "Crypto/sha256.h"
#include "Utilities/File.h"
#include "util/logs.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <algorithm>
#include <iterator>

#include <zlib.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "advapi32.lib")
#else
// POSIX（Linux / Steam Deck）：只借 OpenSSL 做 RSA-OAEP 解封 + ECDSA-P256 验签，
// AES-CTR 用本目录的 aes.cpp（含 AES-NI 路径）。OPENSSL_API_COMPAT 把 1.1 时代 API
// 标成“未弃用”，避免被 -Werror=deprecated-declarations 拦下。
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctime>
#include <cstdlib>
#endif

LOG_CHANNEL(dimg_log, "DIMG");

// DIMG: transparent whole-image decryption + offline activation (v4, RSA-OAEP).
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

namespace dimg
{
	// ---------------------------------------------------------------- constants
	constexpr u64 TAG_OFFSET = 0x1000;
	constexpr u64 TAG_SIZE   = 4096;

	// On-disk magics are stored XOR-masked so they don't show up in `strings` output.
	// （这些常量和 secure_zero 两个平台都要用 —— POSIX 侧同样要伪造 request/license。）
	static constexpr u8 MAGIC_XOR = 0x5A;
	static const u8 TAG_MAGIC_MASKED[8] = {0x0A, 0x09, 0x69, 0x16, 0x19, 0x11, 0x6A, 0x69};

	static bool magic_is(const u8* data, const u8* masked, usz n)
	{
		for (usz i = 0; i < n; i++)
		{
			if (data[i] != static_cast<u8>(masked[i] ^ MAGIC_XOR))
			{
				return false;
			}
		}
		return true;
	}

	static const u8 LICENSE_MAGIC_MASKED[8] = {0x0A, 0x09, 0x69, 0x16, 0x13, 0x19, 0x6A, 0x6E};
	static const u8 REQUEST_MAGIC_MASKED[4] = {0x0A, 0x69, 0x08, 0x0B};
	static const u8 BUNDLE_MAGIC_MASKED[4]  = {0x0A, 0x69, 0x08, 0x02};

	static void magic_put(u8* dst, const u8* masked, usz n)
	{
		for (usz i = 0; i < n; i++)
		{
			dst[i] = static_cast<u8>(masked[i] ^ MAGIC_XOR);
		}
	}

	// Wipes sensitive buffers in a way the optimizer cannot elide.
	static void secure_zero(void* data, usz size)
	{
		volatile u8* p = static_cast<volatile u8*>(data);
		while (size--)
		{
			*p++ = 0;
		}
	}

	constexpr u64 REQ_VER      = 4;
	constexpr u64 LIC_VER      = 4;
	constexpr u64 RSA_BYTES    = 256;              // RSA-2048 modulus / ciphertext
	constexpr u64 BOX_PLAIN    = 48;               // K_iso(32) + iv(16)
	constexpr u64 LIC_HDR_LEN  = 8 + 4 + 16 + 8 + RSA_BYTES;   // 292
	constexpr u64 LIC_SIG_LEN  = 64;               // ECDSA P-256 raw r||s
	constexpr u64 PUB_LEN      = 65;               // issuer pubkey, uncompressed
	constexpr u64 REQ_LEN      = 4 + 4 + RSA_BYTES + 8 + 2;    // 274

	#ifdef _WIN32
	// Windows 档的 issuer 公钥（ECDSA P-256）。换签发密钥时同步改这里。
	// POSIX 档用下面的 ISSUER_PUB_DECK（两档故意分开）。
	static const u8 ISSUER_PUB[PUB_LEN] = {
		0x04, 0x69, 0x26, 0x60, 0x08, 0xCC, 0xB4, 0x4A, 0x2E, 0x4A, 0xC1, 0x99, 0x0A, 0xCA, 0x09, 0x0F, 0xD9, 0xD7, 0xA1, 0x75, 0x7A, 0xA9, 0x40, 0x30, 0x78, 0xAD, 0x64, 0x7E, 0x20, 0xA6, 0xD8, 0x53, 0xCA, 0xA0, 0xCE, 0x84, 0x2D, 0x01, 0xA4, 0x35, 0x4B, 0x08, 0x7B, 0x7D, 0x04, 0x98, 0x61, 0xEB, 0x64, 0xDE, 0xA6, 0x8C, 0x3A, 0x56, 0xDF, 0x87, 0xBE, 0x09, 0xC9, 0x05, 0xA2, 0x2C, 0xFB, 0x84, 0x9D
	};
	#endif

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
		// HKDF-SHA256（RFC 5869）：先 Extract 出 prk，再逐块 Expand。
		// 注意：Expand 的每一块必须是 HMAC(prk, ...)，不是裸 SHA-256。
		u8 prk[32];
		hmac_sha256(salt, sn, ikm, n, prk);

		u8 t[32] = {};
		usz tlen = 0;
		usz done = 0;
		u8 ctr = 1;

		while (done < on)
		{
			std::vector<u8> msg(tlen + in + 1);
			std::memcpy(msg.data(), t, tlen);
			std::memcpy(msg.data() + tlen, info, in);
			msg[tlen + in] = ctr;

			hmac_sha256(prk, sizeof(prk), msg.data(), msg.size(), t);
			tlen = sizeof(t);

			const usz take = std::min<usz>(sizeof(t), on - done);
			std::memcpy(out + done, t, take);
			done += take;
			ctr++;
		}

		secure_zero(prk, sizeof(prk));
		secure_zero(t, sizeof(t));
	}

	// ---------------------------------------------------------------- image key derivation
	// 注意：客户端**从不**自己派生 K_iso（它只从 license 的 RSA-OAEP 匣子里解出来）。
	// 这个函数保留给出包侧自测 / 将来排查用。
	[[maybe_unused]] static void derive_iso_keys(const u8* tag, u8 k_iso[32], u8 iv[16])
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
				crc = (crc & 1) ? static_cast<u16>((crc >> 1) ^ 0xA001) : static_cast<u16>(crc >> 1);
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
		const std::string dir = fs::get_config_dir() + "dimg/";
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

	// Report text is UTF-8 internally (sources build with /utf-8, paths come from to_narrow()).
	// cmd's `type` / Notepad / MessageBoxA want the ANSI code page, so convert once before writing.
	// CP936 first (the .bat switches the console to 936), then the system ANSI page as fallback.
	[[maybe_unused]] static std::string to_ansi(const std::string& utf8)
	{
#ifdef _WIN32
		if (utf8.empty()) return {};

		const int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
		if (wlen <= 0) return utf8;

		std::wstring wide(static_cast<usz>(wlen), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), wlen);

		const UINT cps[2] = {936u, GetACP()};
		for (const UINT cp : cps)
		{
			const int n = WideCharToMultiByte(cp, 0, wide.data(), wlen, nullptr, 0, nullptr, nullptr);
			if (n <= 0) continue;
			std::string out(static_cast<usz>(n), '\0');
			WideCharToMultiByte(cp, 0, wide.data(), wlen, out.data(), n, nullptr, nullptr);
			return out;
		}
		return utf8;
#else
		return utf8;
#endif
	}

	// Notepad and MessageBoxA want CRLF; the report text only ever contains bare '\n'.
	[[maybe_unused]] static std::string to_crlf(const std::string& text)
	{
		std::string out;
		out.reserve(text.size() + text.size() / 16 + 8);
		for (const char c : text)
		{
			if (c == '\n') out += '\r';
			out += c;
		}
		return out;
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
		if (auto d = env_dir(L"LOCALAPPDATA", L"rpcs3\\dimg\\"); !d.empty()) dirs.push_back(d);
		if (auto d = env_dir(L"TEMP", L"rpcs3-dimg\\"); !d.empty()) dirs.push_back(d);
		dirs.push_back(L"C:\\Windows\\Temp\\rpcs3-dimg\\");
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

	// Writes a UTF-8 report as GBK + CRLF (cmd `type`, Notepad and MessageBox all want that).
	static std::string write_text_file(const char* name, const std::string& utf8_text, std::string& status)
	{
		const std::string ansi = to_ansi(to_crlf(utf8_text));
		return write_output(name, ansi.data(), ansi.size(), status);
	}

	// Console output only — the .bat window is the UI, never pop a message box.
	static void print_text(const std::string& utf8_text)
	{
		const std::string shown = to_ansi(to_crlf(utf8_text));
		std::fputs(shown.c_str(), stdout);
		std::fflush(stdout);
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

	static const wchar_t* MACHINE_KEY_NAME = L"rpcs3-dimg-rsa";

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
				err = "打不开密钥存储提供程序";
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
				err = "没有找到机器密钥（请先做激活：--activate）";
				continue;
			}

			NTSTATUS st = NCryptCreatePersistedKey(out.prov, &out.key, BCRYPT_RSA_ALGORITHM, MACHINE_KEY_NAME, 0, 0);
			if (st != ERROR_SUCCESS)
			{
				out.key = 0;
				NCryptFreeObject(out.prov);
				out.prov = 0;
				err = "创建密钥失败：" + ncrypt_error_text(st) + (i == 0 ? "（TPM）" : "（软件 KSP）");
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
				err = "密钥落地失败：" + ncrypt_error_text(st);
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
			err = "导出公钥失败：" + ncrypt_error_text(st);
			return false;
		}

		blob.resize(need);

		// BCRYPT_RSAKEY_BLOB: magic, bitlen, cbPublicExp, cbModulus, cbPrime1, cbPrime2, exp[], mod[]
		if (blob.size() < 24 + 3 + RSA_BYTES)
		{
			err = "公钥数据长度异常";
			return false;
		}

		const u32 magic = read_u32_le(blob.data());
		const u32 cb_exp = read_u32_le(blob.data() + 8);
		const u32 cb_mod = read_u32_le(blob.data() + 12);

		if (magic != BCRYPT_RSAPUBLIC_MAGIC || cb_mod != RSA_BYTES || cb_exp != 3)
		{
			err = "公钥数据格式异常";
			return false;
		}

		std::memcpy(out.modulus, blob.data() + 24 + cb_exp, RSA_BYTES);
		out.valid = true;
		return true;
	}

	// Deletes the persisted machine key from every provider that has it.
	static bool machine_key_delete(std::string& note)
	{
		const wchar_t* providers[2] = {MS_PLATFORM_KEY_STORAGE_PROVIDER, MS_KEY_STORAGE_PROVIDER};
		const char* names[2] = {"TPM", "软件 KSP"};
		bool deleted = false;

		for (int i = 0; i < 2; i++)
		{
			NCRYPT_PROV_HANDLE prov = 0;
			if (NCryptOpenStorageProvider(&prov, providers[i], 0) != ERROR_SUCCESS)
			{
				continue;
			}

			NCRYPT_KEY_HANDLE key = 0;
			if (NCryptOpenKey(prov, &key, MACHINE_KEY_NAME, 0, 0) == ERROR_SUCCESS)
			{
				const NTSTATUS st = NCryptDeleteKey(key, 0);
				if (st == ERROR_SUCCESS)
				{
					deleted = true;
					note += std::string(note.empty() ? "" : ", ") + "已从 " + names[i] + " 删除";
				}
				else
				{
					note += std::string(note.empty() ? "" : ", ") + "在 " + names[i] + " 上删除失败 (" + ncrypt_error_text(st) + ")";
				}
			}

			NCryptFreeObject(prov);
		}

		if (!deleted && note.empty())
		{
			note = "没有找到已存在的机器密钥";
		}
		return deleted;
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
			dimg_log.error("activation key unwrap failed (E2): %s", ncrypt_error_text(st));
			return false;
		}
		out_len = need;
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

#else
	// ---------------------------------------------------------------- POSIX（Linux / Steam Deck）
	//
	// 机器绑定用「指纹派生的 KEK 加密私钥文件」，不依赖 TPM：
	//   ikm     = HMAC-SHA256("dimg-uuid-v1", product_uuid || 0x00 || product_name)
	//   KEK     = HKDF-SHA256(ikm, "dimg-mk-v1", "machine-key")        // 加密私钥
	//   MAC_KEY = HKDF-SHA256(ikm, "dimg-mk-v1", "machine-key-mac")    // 整文件完整性
	// ⇒ 把 ~/.config/rpcs3/dimg/ 拷到另一台 Deck 解不开（指纹不同）。
	// 注意：UUID 是公开信息，所以 **UUID 不进 machine.key.enc，也不进日志**（request.bin 例外）。

	// 平台档：本二进制只认 Steam Deck 档（tag[9] == 1）
	constexpr u8 PROFILE_PLATFORM = 1;

	// 前置声明：license 段在下面（两平台共用），这里的报告/诊断函数要引用
	struct machine_key;
	struct license_info;
	static std::vector<std::string> license_candidates(const std::string& image_path);
	static license_info parse_license(const std::vector<u8>& blob);
	static bool unseal_iso_keys(const license_info& lic, machine_key& mk, u8 k_iso[32], u8 iv[16]);

	// keys/issuer/deck/issuer.pub（65B，uncompressed P-256）；换签发密钥时同步改这里
	static const u8 ISSUER_PUB_DECK[PUB_LEN] = {
		0x04, 0x11, 0x9B, 0xAD, 0x11, 0x6C, 0x37, 0x82, 0xC3, 0x53, 0xD3, 0xBE, 0x86, 0xA5, 0x9C, 0xEB,
		0xA0, 0xBD, 0x55, 0xD5, 0xB8, 0xE6, 0x31, 0x8F, 0xA3, 0x68, 0xA1, 0x02, 0xE1, 0xCE, 0x34, 0x3F,
		0xD5, 0x68, 0x8F, 0xE1, 0x14, 0xC0, 0x7A, 0x15, 0x5E, 0x6C, 0x92, 0xF1, 0xC3, 0xB5, 0x90, 0x9B,
		0xC5, 0x43, 0x2A, 0xC6, 0x9C, 0x2B, 0x13, 0x1C, 0xD0, 0x10, 0x3A, 0xA8, 0x47, 0x57, 0xA3, 0xFE,
		0x48
	};

	struct machine_key
	{
		bool valid = false;
		bool used_tpm = false;          // POSIX 侧永远是软件密钥（以后接 tpm2-tss 再打开）
		std::vector<u8> der;            // PKCS#1 私钥 DER，用完擦
		u8 modulus[RSA_BYTES] = {};
		std::string note;
	};

	// ---------------------------------------------------------------- 文件小工具
	static bool read_file_bytes(const std::string& path, std::vector<u8>& out)
	{
		std::FILE* f = std::fopen(path.c_str(), "rb");
		if (!f)
		{
			return false;
		}
		std::fseek(f, 0, SEEK_END);
		const long n = std::ftell(f);
		std::fseek(f, 0, SEEK_SET);
		if (n < 0)
		{
			std::fclose(f);
			return false;
		}
		out.resize(static_cast<usz>(n));
		const usz got = out.empty() ? 0 : std::fread(out.data(), 1, out.size(), f);
		std::fclose(f);
		return got == out.size();
	}

	static bool file_exists(const std::string& path)
	{
		std::FILE* f = std::fopen(path.c_str(), "rb");
		if (!f)
		{
			return false;
		}
		std::fclose(f);
		return true;
	}

	static bool write_file_bytes(const std::string& path, const void* data, usz size, std::string& err)
	{
		std::FILE* f = std::fopen(path.c_str(), "wb");
		if (!f)
		{
			err = "打不开 " + path;
			return false;
		}
		const bool ok = size == 0 || std::fwrite(data, 1, size, f) == size;
		std::fclose(f);
		if (!ok)
		{
			err = "写不进去 " + path;
			return false;
		}
		::chmod(path.c_str(), S_IRUSR | S_IWUSR);
		return true;
	}

	static std::string trim_copy(std::string s)
	{
		while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
		while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
		return s;
	}

	static std::string read_text_trimmed(const std::string& path)
	{
		std::vector<u8> b;
		if (!read_file_bytes(path, b))
		{
			return {};
		}
		return trim_copy(std::string(b.begin(), b.end()));
	}

	// ---------------------------------------------------------------- 机器指纹
	static std::string path_root()
	{
#ifdef DIMG_SELFTEST_FINGERPRINT
		// 只有 tools/deck_port 的离线自测会定义这个宏，用来把 /sys、/etc 指到假根目录
		if (const char* r = std::getenv("DIMG_TEST_SYSROOT"))
		{
			return r;
		}
#endif
		return {};
	}

	static std::string dmi_field(const char* name)
	{
		return read_text_trimmed(path_root() + std::string("/sys/class/dmi/id/") + name);
	}

	// 机器标识候选（按优先级）。不同机器暴露的东西不一样：Steam Deck 常常没有 product_uuid
	// （SMBIOS type-1 字符串为空时内核干脆不建这个文件），但一定有 /etc/machine-id。
	// 指纹只用于派生 KEK，用哪个都行 —— 越靠前越好。
	struct fp_candidate
	{
		std::string value;
		std::string name;    // product_name，放进 ikm 当盐
		std::string source;  // 给人看的来源说明
	};

	static std::string read_or_create_install_id()
	{
		const std::string path = config_dir() + "machine-id.txt";
		const std::string v = read_text_trimmed(path);
		if (!v.empty())
		{
			return v;
		}

		u8 rnd[16] = {};
		if (RAND_bytes(rnd, sizeof(rnd)) != 1)
		{
			return {};
		}

		char buf[3];
		std::string hex;
		for (const u8 c : rnd)
		{
			std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(c));
			hex += buf;
		}

		std::string err;
		if (!write_file_bytes(path, hex.data(), hex.size(), err))
		{
			return {};
		}
		return hex;
	}

	static std::vector<fp_candidate> fingerprint_candidates()
	{
		std::vector<fp_candidate> out;

#ifdef DIMG_SELFTEST_FINGERPRINT
		// 只有 tools/deck_port 的离线自测会定义这个宏；正式构建里不存在
		if (const char* u = std::getenv("DIMG_TEST_UUID"))
		{
			out.push_back({u, std::getenv("DIMG_TEST_PRODUCT") ? std::getenv("DIMG_TEST_PRODUCT") : "Jupiter", "selftest"});
			return out;
		}
#endif

		const std::string pname = dmi_field("product_name");

		const auto add = [&](const char* source, const std::string& raw)
		{
			const std::string v = trim_copy(raw);
			if (v.size() < 8)
			{
				return;
			}
			for (const char* bad : {"00000000-0000-0000-0000-000000000000",
				"03000200-0400-0500-0006-000700080009", "Not Specified", "To be filled by O.E.M.",
				"Default string", "System Serial Number", "None"})
			{
				if (v == bad)
				{
					return;
				}
			}
			for (const fp_candidate& c : out)
			{
				if (c.value == v)
				{
					return;   // 去重（product_serial 与 board_serial 常常一样）
				}
			}
			out.push_back({v, pname, source});
		};

		add("dmi:product_uuid", dmi_field("product_uuid"));
		add("dmi:board_serial", dmi_field("board_serial"));
		add("dmi:product_serial", dmi_field("product_serial"));
		add("os:machine-id", read_text_trimmed(path_root() + "/etc/machine-id"));
		add("os:install-id", read_or_create_install_id());   // 最后兜底：本机随机生成，存在配置目录

		return out;
	}

	// 列进 activate.txt / diag.txt，排障用
	static std::string fingerprint_report_text(const std::vector<fp_candidate>& cands, const std::string& used)
	{
		std::string out = "指纹来源     : ";
		if (cands.empty())
		{
			return out + "（全部不可用！）\n";
		}
		out += (used.empty() ? cands.front().source : used) + "\n";
		for (const fp_candidate& c : cands)
		{
			addf(out, "               %-18s %s\n", (c.source + ":").c_str(), c.value.c_str());
		}
		return out;
	}

	static u64 hwid_hash8()
	{
		std::string anchor = "unknown";
		if (const std::vector<fp_candidate> cands = fingerprint_candidates(); !cands.empty())
		{
			anchor = cands.front().value;
		}

		static const u8 key[12] = {'d','i','m','g','-','h','w','i','d','-','v','1'};
		u8 digest[32];
		hmac_sha256(key, sizeof(key), reinterpret_cast<const u8*>(anchor.data()), anchor.size(), digest);

		u64 v = 0;
		for (int i = 0; i < 8; i++) v = (v << 8) | digest[i];
		return v;
	}

	// ---------------------------------------------------------------- 机器密钥文件（machine.key.enc）
	static const u8 MK_MAGIC[8] = {'D','I','M','G','M','K','0','1'};
	constexpr u64 MK_HDR = 8 + 4 + 16 + 4;          // magic | ver/flags/res | nonce(16) | ct_len(4)

	static std::string machine_key_path()
	{
		return config_dir() + "machine.key.enc";
	}

	static void fingerprint_ikm(const std::string& uuid, const std::string& name, u8 ikm[32])
	{
		std::string msg = uuid;
		msg.push_back('\0');
		msg += name;

		static const u8 key[12] = {'d','i','m','g','-','u','u','i','d','-','v','1'};
		hmac_sha256(key, sizeof(key), reinterpret_cast<const u8*>(msg.data()), msg.size(), ikm);
	}

	static void derive_machine_keys(const u8 ikm[32], u8 kek[32], u8 mac_key[32])
	{
		static const u8 salt[10]  = {'d','i','m','g','-','m','k','-','v','1'};
		static const u8 i_kek[11] = {'m','a','c','h','i','n','e','-','k','e','y'};
		static const u8 i_mac[15] = {'m','a','c','h','i','n','e','-','k','e','y','-','m','a','c'};

		hkdf_sha256(ikm, 32, salt, sizeof(salt), i_kek, sizeof(i_kek), kek, 32);
		hkdf_sha256(ikm, 32, salt, sizeof(salt), i_mac, sizeof(i_mac), mac_key, 32);
	}

	static void aes_ctr(const u8 key[32], const u8 nonce[16], const void* in, void* out, usz len)
	{
		aes_context ctx;
		aes_setkey_enc(&ctx, key, 256);

		u8 counter[16];
		std::memcpy(counter, nonce, 16);

		usz nc_off = 0;
		u8 stream_block[16] = {};
		aes_crypt_ctr(&ctx, len, &nc_off, counter, stream_block,
			static_cast<const u8*>(in), static_cast<u8*>(out));

		secure_zero(&ctx, sizeof(ctx));
		secure_zero(counter, sizeof(counter));
		secure_zero(stream_block, sizeof(stream_block));
	}

	static EVP_PKEY* evp_from_der(const std::vector<u8>& der)
	{
		const unsigned char* p = der.data();
		return d2i_AutoPrivateKey(nullptr, &p, static_cast<long>(der.size()));
	}

	static bool load_machine_key(machine_key& out, const u8 ikm[32], std::string& err)
	{
		std::vector<u8> blob;
		if (!read_file_bytes(machine_key_path(), blob))
		{
			err = "没有机器密钥文件（" + machine_key_path() + "）";
			return false;
		}
		if (blob.size() < MK_HDR + 32 || std::memcmp(blob.data(), MK_MAGIC, 8) != 0 || blob[8] != 1)
		{
			err = "机器密钥文件格式不符（" + machine_key_path() + "）";
			return false;
		}

		const u32 ct_len = (u32(blob[28]) << 24) | (u32(blob[29]) << 16) | (u32(blob[30]) << 8) | u32(blob[31]);
		if (blob.size() != MK_HDR + ct_len + 32)
		{
			err = "机器密钥文件长度不对";
			return false;
		}

		u8 kek[32], mac_key[32];
		derive_machine_keys(ikm, kek, mac_key);

		u8 want[32];
		hmac_sha256(mac_key, 32, blob.data(), MK_HDR + ct_len, want);
		if (std::memcmp(want, blob.data() + MK_HDR + ct_len, 32) != 0)
		{
			err = "机器密钥打不开：不是这台机器的（指纹不符，可能拷了别的机器或换过主板）";
			secure_zero(kek, sizeof(kek));
			secure_zero(mac_key, sizeof(mac_key));
			return false;
		}

		out.der.resize(ct_len);
		aes_ctr(kek, blob.data() + 12, blob.data() + MK_HDR, out.der.data(), ct_len);
		secure_zero(kek, sizeof(kek));
		secure_zero(mac_key, sizeof(mac_key));

		EVP_PKEY* pk = evp_from_der(out.der);
		if (!pk)
		{
			err = "机器密钥内容无效";
			out.der.clear();
			return false;
		}
		const RSA* rsa = EVP_PKEY_get0_RSA(pk);
		const BIGNUM* n = nullptr;
		if (rsa)
		{
			RSA_get0_key(rsa, &n, nullptr, nullptr);
		}
		if (!n || BN_bn2binpad(n, out.modulus, RSA_BYTES) != RSA_BYTES)
		{
			EVP_PKEY_free(pk);
			err = "机器公钥导出失败";
			return false;
		}
		EVP_PKEY_free(pk);

		out.valid = true;
		out.used_tpm = false;
		return true;
	}

	static bool store_machine_key(const std::vector<u8>& der, const u8 ikm[32], std::string& err)
	{
		u8 kek[32], mac_key[32];
		derive_machine_keys(ikm, kek, mac_key);

		u8 nonce[16] = {};
		if (RAND_bytes(nonce, sizeof(nonce)) != 1)
		{
			err = "随机数源不可用";
			return false;
		}

		const usz ct_len = der.size();
		std::vector<u8> blob(MK_HDR + ct_len + 32);
		std::memcpy(blob.data(), MK_MAGIC, 8);
		blob[8] = 1;
		std::memcpy(blob.data() + 12, nonce, 16);
		blob[28] = static_cast<u8>((ct_len >> 24) & 0xFF);
		blob[29] = static_cast<u8>((ct_len >> 16) & 0xFF);
		blob[30] = static_cast<u8>((ct_len >> 8) & 0xFF);
		blob[31] = static_cast<u8>(ct_len & 0xFF);

		aes_ctr(kek, nonce, der.data(), blob.data() + MK_HDR, ct_len);
		hmac_sha256(mac_key, 32, blob.data(), MK_HDR + ct_len, blob.data() + MK_HDR + ct_len);

		secure_zero(kek, sizeof(kek));
		secure_zero(mac_key, sizeof(mac_key));
		secure_zero(nonce, sizeof(nonce));

		return write_file_bytes(machine_key_path(), blob.data(), blob.size(), err);
	}

	static bool machine_key_open(machine_key& out, bool create, std::string& err)
	{
		if (out.valid)
		{
			return true;
		}

		const std::vector<fp_candidate> cands = fingerprint_candidates();
		if (cands.empty())
		{
			err = "读不到任何机器标识（product_uuid / 板载串号 / /etc/machine-id 全不可用）";
			return false;
		}

		// ① 已有密钥文件：逐个候选试着开（内核更新或锚点变化后能自愈，不必重新激活）
		if (file_exists(machine_key_path()))
		{
			std::string last;
			for (const fp_candidate& c : cands)
			{
				u8 ikm[32];
				fingerprint_ikm(c.value, c.name, ikm);

				machine_key probe;
				const bool ok = load_machine_key(probe, ikm, last);
				secure_zero(ikm, sizeof(ikm));

				if (ok)
				{
					out = std::move(probe);
					out.note = c.source;
					return true;
				}
			}

			std::string tried;
			for (const fp_candidate& c : cands)
			{
				tried += (tried.empty() ? "" : " / ") + c.source;
			}
			err = last + "（已按顺序试过：" + tried + "）；可用 --reset-key 重建，但那会让已发出的 license 失效";
			return false;
		}

		if (!create)
		{
			err = "没有机器密钥文件（" + machine_key_path() + "），请先做激活（--activate）";
			return false;
		}

		// ② 新建：用优先级最高的候选（有 product_uuid 就用它，没有就退到 machine-id 等）
		const fp_candidate& best = cands.front();

		std::vector<u8> der;
		{
			RSA* rsa = RSA_new();
			BIGNUM* e = BN_new();
			bool ok = rsa && e && BN_set_word(e, RSA_F4) == 1 && RSA_generate_key_ex(rsa, 2048, e, nullptr) == 1;
			if (ok)
			{
				unsigned char* q = nullptr;
				const int n = i2d_RSAPrivateKey(rsa, &q);
				if (n > 0)
				{
					der.assign(q, q + n);
				}
				else
				{
					ok = false;
				}
				if (q)
				{
					OPENSSL_cleanse(q, static_cast<usz>(n > 0 ? n : 0));
					OPENSSL_free(q);
				}
			}
			if (rsa) RSA_free(rsa);
			if (e) BN_free(e);

			if (!ok)
			{
				err = "RSA-2048 生成失败";
				return false;
			}
		}

		u8 ikm[32];
		fingerprint_ikm(best.value, best.name, ikm);
		const bool stored = store_machine_key(der, ikm, err);
		secure_zero(ikm, sizeof(ikm));
		if (!stored)
		{
			return false;
		}

		u8 ikm2[32];
		fingerprint_ikm(best.value, best.name, ikm2);
		const bool reloaded = load_machine_key(out, ikm2, err);
		secure_zero(ikm2, sizeof(ikm2));
		out.note = best.source;
		return reloaded;
	}

	static bool machine_key_delete(std::string& note)
	{
		const std::string path = machine_key_path();
		if (!file_exists(path))
		{
			note = "没有机器密钥文件";
			return false;
		}
		if (::unlink(path.c_str()) != 0)
		{
			note = "删除失败：" + path;
			return false;
		}
		note = "已删除 " + path;
		return true;
	}

	// ---------------------------------------------------------------- RSA-OAEP（OpenSSL）
	static bool rsa_oaep_decrypt(machine_key& mk, const u8* in, u8* out, u32& out_len)
	{
		if (!mk.valid || mk.der.empty())
		{
			return false;
		}

		EVP_PKEY* pk = evp_from_der(mk.der);
		if (!pk)
		{
			return false;
		}

		bool ok = false;
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pk, nullptr);
		if (ctx && EVP_PKEY_decrypt_init(ctx) == 1 &&
			EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1 &&
			EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) == 1 &&
			EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) == 1)
		{
			// OpenSSL 要求输出缓冲至少 RSA_size（256B），解完再裁到 BOX_PLAIN
			u8 tmp[RSA_BYTES] = {};
			usz n = sizeof(tmp);
			if (EVP_PKEY_decrypt(ctx, tmp, &n, in, RSA_BYTES) == 1 && n == BOX_PLAIN)
			{
				std::memcpy(out, tmp, BOX_PLAIN);
				out_len = BOX_PLAIN;
				ok = true;
			}
			secure_zero(tmp, sizeof(tmp));
		}
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pk);
		return ok;
	}

	static bool ecdsa_p256_verify(const u8* hash32, const u8* sig64)
	{
		if (ISSUER_PUB_DECK[0] != 0x04)
		{
			return false;
		}

		EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (!ec)
		{
			return false;
		}

		// 公钥：65B uncompressed (0x04 || X || Y)
		const EC_GROUP* group = EC_KEY_get0_group(ec);
		EC_POINT* pt = EC_POINT_new(group);
		BIGNUM* x = BN_bin2bn(ISSUER_PUB_DECK + 1, 32, nullptr);
		BIGNUM* y = BN_bin2bn(ISSUER_PUB_DECK + 33, 32, nullptr);

		bool ok = false;
		if (pt && x && y &&
			EC_POINT_set_affine_coordinates(group, pt, x, y, nullptr) == 1 &&
			EC_KEY_set_public_key(ec, pt) == 1)
		{
			// 签名是 raw r||s（64B，和 Windows/CNG 侧同格式）；OpenSSL 的 EC API 要 ECDSA_SIG
			ECDSA_SIG* sig = ECDSA_SIG_new();
			BIGNUM* r = BN_bin2bn(sig64, 32, nullptr);
			BIGNUM* ss = BN_bin2bn(sig64 + 32, 32, nullptr);
			if (sig && r && ss)
			{
				// 3.x 起 ECDSA_SIG_set0 只存在于 1.1+；老版本用 ->r/->s 直接赋值
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
				ECDSA_SIG_set0(sig, r, ss);
#else
				sig->r = r;
				sig->s = ss;
#endif
				ok = ECDSA_do_verify(hash32, 32, sig, ec) == 1;
				ECDSA_SIG_free(sig);
			}
			else
			{
				BN_free(r);
				BN_free(ss);
				ECDSA_SIG_free(sig);
			}
		}

		EC_POINT_free(pt);
		BN_free(x);
		BN_free(y);
		EC_KEY_free(ec);
		return ok;
	}

	// ---------------------------------------------------------------- 输出 / 报告
	static std::string exe_dir()
	{
		char buf[4096] = {};
		const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
		if (n <= 0)
		{
			return {};
		}
		const std::string path(buf, static_cast<usz>(n));
		const usz slash = path.find_last_of('/');
		return slash == std::string::npos ? std::string(".") : path.substr(0, slash + 1);
	}

	// 写到配置目录（$HOME 持久；绝不写只读的 /usr 或 /etc）
	static std::string write_text_file(const char* name, const std::string& utf8_text, std::string& status)
	{
		const std::string path = config_dir() + name;
		std::string err;
		if (!write_file_bytes(path, utf8_text.data(), utf8_text.size(), err))
		{
			status = err;
			return {};
		}
		return path;
	}

	static void print_text(const std::string& utf8_text)
	{
		std::fputs(utf8_text.c_str(), stdout);
		std::fflush(stdout);
	}

	static std::string machine_info_text()
	{
		std::string out = "=== 机器信息 ===\n";

		char stamp[64] = {};
		const std::time_t now = std::time(nullptr);
		std::tm tmv{};
		localtime_r(&now, &tmv);
		std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv);
		out += std::string("报告时间     : ") + stamp + "\n";

		char host[256] = {};
		if (::gethostname(host, sizeof(host) - 1) == 0)
		{
			out += std::string("计算机名     : ") + host + "\n";
		}

		std::string os_name;
		{
			std::vector<u8> b;
			if (read_file_bytes("/etc/os-release", b))
			{
				const std::string txt(b.begin(), b.end());
				const usz p = txt.find("PRETTY_NAME=");
				if (p != std::string::npos)
				{
					const usz e = txt.find('\n', p);
					std::string v = txt.substr(p + 12, e == std::string::npos ? std::string::npos : e - p - 12);
					for (char& c : v) if (c == '"' || c == '\'') c = ' ';
					os_name = trim_copy(v);
				}
			}
		}
		if (!os_name.empty())
		{
			out += "操作系统     : " + os_name + "\n";
		}

		const std::string product = dmi_field("product_name");
		if (!product.empty())
		{
			out += "机型         : " + product + "\n";
		}

		{
			std::vector<u8> b;
			if (read_file_bytes("/proc/cpuinfo", b))
			{
				const std::string txt(b.begin(), b.end());
				const usz p = txt.find("model name");
				if (p != std::string::npos)
				{
					const usz c = txt.find(':', p);
					const usz e = txt.find('\n', c == std::string::npos ? p : c);
					if (c != std::string::npos)
					{
						out += "处理器       : " + trim_copy(txt.substr(c + 1, e == std::string::npos ? std::string::npos : e - c - 1)) + "\n";
					}
				}
			}
		}

		{
			std::vector<u8> b;
			if (read_file_bytes("/proc/meminfo", b))
			{
				const std::string txt(b.begin(), b.end());
				const usz p = txt.find("MemTotal:");
				const usz e = txt.find('\n', p);
				if (p != std::string::npos && e != std::string::npos)
				{
					out += "物理内存     : " + trim_copy(txt.substr(p + 9, e - p - 9)) + "\n";
				}
			}
		}

		// 明文标识只出现在 request.bin（出包侧本来就有 master.key，不算额外暴露）
		out += fingerprint_report_text(fingerprint_candidates(), std::string{});

		out += "程序目录     : " + exe_dir() + "\n";
		out += "配置目录     : " + config_dir() + "\n";
		return out;
	}

	static void add_be32(std::string& out, u32 v)
	{
		out += static_cast<char>((v >> 24) & 0xFF);
		out += static_cast<char>((v >> 16) & 0xFF);
		out += static_cast<char>((v >> 8) & 0xFF);
		out += static_cast<char>(v & 0xFF);
	}

	static std::string deflate_zlib(const std::string& plain)
	{
		if (plain.empty() || plain.size() > 0x100000)
		{
			return {};
		}

		uLongf size = compressBound(static_cast<uLong>(plain.size()));
		std::string out(size, '\0');
		if (compress2(reinterpret_cast<Bytef*>(out.data()), &size,
			reinterpret_cast<const Bytef*>(plain.data()), static_cast<uLong>(plain.size()), 9) != Z_OK)
		{
			return {};
		}
		out.resize(size);
		return out;
	}

	std::string build_request_with_report(const u8* core, usz core_len, const std::string& report_utf8)
	{
		std::string blob(reinterpret_cast<const char*>(core), core_len);
		const std::string packed = deflate_zlib(report_utf8);

		if (packed.empty() || packed.size() > 0xFFFF)
		{
			return blob;   // 压缩不可用就只发 274 B：授权语义完全不变
		}

		u8 header_magic[4];
		magic_put(header_magic, BUNDLE_MAGIC_MASKED, 4);

		std::string head(reinterpret_cast<const char*>(header_magic), sizeof(header_magic));
		head += static_cast<char>(1);   // version
		head += static_cast<char>(1);   // method: 1 = zlib deflate
		head += static_cast<char>(0);
		head += static_cast<char>(0);
		add_be32(head, static_cast<u32>(packed.size()));
		add_be32(head, static_cast<u32>(report_utf8.size()));

		const u16 crc = crc16(reinterpret_cast<const u8*>(head.data()), head.size());
		head += static_cast<char>((crc >> 8) & 0xFF);
		head += static_cast<char>(crc & 0xFF);

		return blob + head + packed;
	}

#endif

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
		if (const char* home = std::getenv("HOME"))
		{
			// Flatpak 版 RPCS3 的配置目录（两个 RPCS3 并存的 Deck 上很常见）
			out.push_back(std::string(home) + "/.var/app/net.rpcs3.RPCS3/config/rpcs3/dimg/license.bin");
		}

		std::vector<std::string> uniq;
		for (const std::string& p : out)
		{
			if (std::find(uniq.begin(), uniq.end(), p) == uniq.end())
			{
				uniq.push_back(p);
			}
		}
		return uniq;
	}

	static license_info parse_license(const std::vector<u8>& blob)
	{
		license_info info;
		if (blob.size() != LIC_HDR_LEN + TAG_SIZE + LIC_SIG_LEN || !magic_is(blob.data(), LICENSE_MAGIC_MASKED, 8))
		{
			info.error = "授权数据格式不符（E1）";
			return info;
		}
		if (blob[8] != LIC_VER)
		{
			info.error = "授权数据版本不符（E1）";
			return info;
		}

		u8 hash[32];
		hash_sha256(blob.data(), LIC_HDR_LEN + TAG_SIZE, hash);
		if (!ecdsa_p256_verify(hash, blob.data() + LIC_HDR_LEN + TAG_SIZE))
		{
			info.error = "授权数据校验失败（E2）";
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
			secure_zero(plain, sizeof(plain));
			return false;
		}

		std::memcpy(k_iso, plain, 32);
		std::memcpy(iv, plain + 32, 16);
		secure_zero(plain, sizeof(plain));
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
		~lock_file() override
		{
			secure_zero(m_k_iso, sizeof(m_k_iso));
			secure_zero(m_iv, sizeof(m_iv));
		}

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

			secure_zero(keystream.data(), keystream.size());
			secure_zero(stream_block, sizeof(stream_block));
			secure_zero(&ctx, sizeof(ctx));

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

	// ---------------------------------------------------------------- reports / machine info
#ifdef _WIN32
	static void add_be32(std::string& out, u32 v)
	{
		out += static_cast<char>((v >> 24) & 0xFF);
		out += static_cast<char>((v >> 16) & 0xFF);
		out += static_cast<char>((v >> 8) & 0xFF);
		out += static_cast<char>(v & 0xFF);
	}

	// zlib (RFC1950) wrapper — the same stream `zlib.decompress()` eats on the signing side.
	static std::string deflate_zlib(const std::string& plain)
	{
		if (plain.empty() || plain.size() > 0x100000)
		{
			return {};
		}

		uLongf size = compressBound(static_cast<uLong>(plain.size()));
		std::string out(size, '\0');
		if (compress2(reinterpret_cast<Bytef*>(out.data()), &size,
			reinterpret_cast<const Bytef*>(plain.data()), static_cast<uLong>(plain.size()), 9) != Z_OK)
		{
			return {};
		}
		out.resize(size);
		return out;
	}

	static std::string env_utf8(const wchar_t* name)
	{
		wchar_t buf[512] = {};
		const DWORD n = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
		if (!n || n >= std::size(buf))
		{
			return {};
		}
		return to_narrow(std::wstring(buf, n));
	}

	static std::string reg_string(HKEY root, const wchar_t* sub, const wchar_t* name)
	{
		wchar_t buf[256] = {};
		DWORD size = sizeof(buf);
		if (RegGetValueW(root, sub, name, RRF_RT_REG_SZ, nullptr, buf, &size) != ERROR_SUCCESS)
		{
			return {};
		}
		return to_narrow(std::wstring(buf));
	}

	// Everything the signing side wants to keep, kept OUT of the on-screen text.
	static std::string machine_info_text()
	{
		std::string out = "=== 机器信息 ===\n";

		SYSTEMTIME st{};
		GetLocalTime(&st);
		addf(out, "报告时间     : %04u-%02u-%02u %02u:%02u:%02u\n",
			unsigned(st.wYear), unsigned(st.wMonth), unsigned(st.wDay),
			unsigned(st.wHour), unsigned(st.wMinute), unsigned(st.wSecond));

		wchar_t computer[256] = {};
		DWORD csize = static_cast<DWORD>(std::size(computer));
		if (GetComputerNameW(computer, &csize))
		{
			out += "计算机名     : " + to_narrow(std::wstring(computer, csize)) + "\n";
		}

		const wchar_t* cv = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
		const std::string product = reg_string(HKEY_LOCAL_MACHINE, cv, L"ProductName");
		const std::string build = reg_string(HKEY_LOCAL_MACHINE, cv, L"CurrentBuild");
		const std::string display = reg_string(HKEY_LOCAL_MACHINE, cv, L"DisplayVersion");
		if (!product.empty() || !build.empty())
		{
			std::string os = product;
			if (!display.empty()) os += " " + display;
			if (!build.empty()) os += " (build " + build + ")";
			out += "操作系统     : " + os + "\n";
		}

		if (const std::string cpu = env_utf8(L"PROCESSOR_IDENTIFIER"); !cpu.empty())
		{
			out += "处理器       : " + cpu + "\n";
		}

		MEMORYSTATUSEX mem{};
		mem.dwLength = sizeof(mem);
		if (GlobalMemoryStatusEx(&mem))
		{
			addf(out, "物理内存     : %llu MB\n", static_cast<unsigned long long>(mem.ullTotalPhys >> 20));
		}

		out += "程序目录     : " + to_narrow(exe_dir()) + "\n";
		return out;
	}

	struct diagnose_result
	{
		std::string text;
		bool active = false;
		std::string reason;
	};

	// One line summary + the verbose dump. `active` means: this machine's key really opens the license box.
	static diagnose_result build_diagnose_text(machine_key& mk, bool have_key, const std::string& err)
	{
		diagnose_result res;
		std::string& out = res.text;

		addf(out, "=== 激活状态检查 ===\n\n");
		if (have_key)
		{
			addf(out, "机器密钥     : 已存在\n");
			addf(out, "密钥类型     : %s\n", mk.used_tpm ? "TPM（密钥不可导出）" : "软件 KSP（密钥不可导出）");
			if (!mk.used_tpm && !mk.note.empty())
			{
				addf(out, "TPM 说明     : %s\n", mk.note.c_str());
			}
			addf(out, "公钥前 16 字节: ");
			hex_into(out, mk.modulus, 16);
			addf(out, "\n");
		}
		else
		{
			addf(out, "机器密钥     : 缺失（%s）\n", err.c_str());
		}
		addf(out, "配置目录     : %s\n\n", config_dir().c_str());

		for (const std::string& candidate : license_candidates(""))
		{
			fs::file lf(candidate);
			if (!lf)
			{
				addf(out, "授权文件     : %s  （未找到）\n", candidate.c_str());
				continue;
			}

			std::vector<u8> blob(lf.size());
			lf.read(blob.data(), blob.size());
			const license_info lic = parse_license(blob);
			addf(out, "授权文件     : %s  -> %s\n", candidate.c_str(), lic.ok ? "签名有效 (valid signature)" : lic.error.c_str());

			if (!lic.ok)
			{
				if (res.reason.empty()) res.reason = "授权文件无效：" + lic.error;
				continue;
			}

			addf(out, "收件人编号   : ");
			hex_into(out, lic.recipient, 16);
			addf(out, "\n");

			// The only honest test: can *this* machine's persisted key open the license box?
			u8 k_iso[32];
			u8 iv[16];
			if (have_key && unseal_iso_keys(lic, mk, k_iso, iv))
			{
				res.active = true;
				res.reason = "已安装授权，且与本机密钥匹配";
			}
			else if (res.reason.empty())
			{
				res.reason = have_key ? "授权文件与本机不匹配（不是这台机器的 license）" : "缺少机器密钥";
			}
		}

		if (!res.active && res.reason.empty())
		{
			res.reason = "还没有安装授权文件";
		}

		return res;
	}

	// request.bin = 274 B request + "P3RX" zlib bundle: the signing side keeps the whole story.
	static std::string build_request_with_report(const u8* core, usz core_len, const std::string& report_utf8)
	{
		std::string blob(reinterpret_cast<const char*>(core), core_len);
		const std::string packed = deflate_zlib(report_utf8);

		if (packed.empty() || packed.size() > 0xFFFF)
		{
			return blob;   // 压缩不可用就只发 274 B：授权语义完全不变
		}

		u8 header_magic[4];
		magic_put(header_magic, BUNDLE_MAGIC_MASKED, 4);

		std::string head(reinterpret_cast<const char*>(header_magic), sizeof(header_magic));
		head += static_cast<char>(1);   // version
		head += static_cast<char>(1);   // method: 1 = zlib deflate
		head += static_cast<char>(0);
		head += static_cast<char>(0);
		add_be32(head, static_cast<u32>(packed.size()));
		add_be32(head, static_cast<u32>(report_utf8.size()));

		const u16 crc = crc16(reinterpret_cast<const u8*>(head.data()), head.size());
		head += static_cast<char>((crc >> 8) & 0xFF);
		head += static_cast<char>(crc & 0xFF);

		return blob + head + packed;
	}
#else
	// POSIX：与 Windows 同形的诊断文本（license/密钥定义都在上面了）
	struct diagnose_result
	{
		std::string text;
		bool active = false;
		std::string reason;
	};

	static diagnose_result build_diagnose_text(machine_key& mk, bool have_key, const std::string& err)
	{
		diagnose_result res;
		std::string& out = res.text;

		addf(out, "=== 激活状态检查 ===\n\n");
		if (have_key)
		{
			addf(out, "机器密钥     : 已存在\n");
			addf(out, "密钥类型     : 软件密钥（指纹派生的 KEK 加密）\n");
			addf(out, "指纹来源     : %s\n", mk.note.empty() ? "未知" : mk.note.c_str());
			addf(out, "密钥文件     : %s\n", machine_key_path().c_str());
			addf(out, "公钥前 16 字节: ");
			hex_into(out, mk.modulus, 16);
			addf(out, "\n");
		}
		else
		{
			addf(out, "机器密钥     : 缺失（%s）\n", err.c_str());
		}
		addf(out, "平台档       : Steam Deck（tag[9] = %u）\n", unsigned(PROFILE_PLATFORM));
		addf(out, "配置目录     : %s\n\n", config_dir().c_str());

		for (const std::string& candidate : license_candidates(""))
		{
			fs::file lf(candidate);
			if (!lf)
			{
				addf(out, "授权文件     : %s  （未找到）\n", candidate.c_str());
				continue;
			}

			std::vector<u8> blob(lf.size());
			lf.read(blob.data(), blob.size());
			const license_info lic = parse_license(blob);
			addf(out, "授权文件     : %s  -> %s\n", candidate.c_str(), lic.ok ? "签名有效 (valid signature)" : lic.error.c_str());

			if (!lic.ok)
			{
				if (res.reason.empty()) res.reason = "授权文件无效：" + lic.error;
				continue;
			}

			addf(out, "收件人编号   : ");
			hex_into(out, lic.recipient, 16);
			addf(out, "\n");

			u8 k_iso[32];
			u8 iv[16];
			if (have_key && unseal_iso_keys(lic, mk, k_iso, iv))
			{
				secure_zero(k_iso, sizeof(k_iso));
				secure_zero(iv, sizeof(iv));
				res.active = true;
				res.reason = "已安装授权，且与本机密钥匹配";
			}
			else if (res.reason.empty())
			{
				res.reason = have_key ? "授权文件与本机不匹配（不是这台机器的 license）" : "缺少机器密钥";
			}
		}

		if (!res.active && res.reason.empty())
		{
			res.reason = "还没有安装授权文件";
		}

		return res;
	}
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

		return magic_is(tag, TAG_MAGIC_MASKED, sizeof(TAG_MAGIC_MASKED));
	}

	fs::file open_maybe_locked(const std::string& path, bs_t<fs::open_mode> mode)
	{
		fs::file file(path, mode);

		if (!is_locked(file))
		{
			return file;
		}

#ifdef _WIN32
		dimg_log.notice("image layer: %s", path);

		u8 tag[TAG_SIZE];
		if (!read_exact(file, TAG_OFFSET, tag, sizeof(tag)))
		{
			dimg_log.error("image header unreadable: %s", path);
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
				dimg_log.notice("activation data: %s", candidate);
				break;
			}
			dimg_log.error("activation %s: %s", candidate, lic.error);
		}

		if (!lic.ok)
		{
			dimg_log.error("no activation data found (searched next to the image, the working dir and %s) — "
				"run rpcs3.exe --activate first", config_dir());
			return fs::file{};
		}

		if (std::memcmp(lic.tag.data(), tag, TAG_SIZE) != 0)
		{
			dimg_log.error("activation data does not match this image (E4)");
			return fs::file{};
		}

		machine_key mk;
		std::string err;
		if (!machine_key_open(mk, false, err))
		{
			dimg_log.error("device key unavailable (E5): %s", err);
			return fs::file{};
		}

		u8 k_iso[32];
		u8 iv[16];
		if (!unseal_iso_keys(lic, mk, k_iso, iv))
		{
			dimg_log.error("activation does not open on this device (E6, %s, %s)", config_dir(), mk.used_tpm ? "TPM" : "software KSP");
			return fs::file{};
		}

		const u64 size = file.size();
		dimg_log.notice("activation OK (%02x%02x%02x%02x…, %s), decrypting on demand",
			unsigned(lic.recipient[0]), unsigned(lic.recipient[1]), unsigned(lic.recipient[2]), unsigned(lic.recipient[3]),
			mk.used_tpm ? "TPM-held RSA key" : "software-held RSA key");

		fs::file out(std::unique_ptr<fs::file_base>(new lock_file(std::move(file), size, k_iso, iv)));
		secure_zero(k_iso, sizeof(k_iso));
		secure_zero(iv, sizeof(iv));
		return out;
#else
		// POSIX（Steam Deck / Linux）：同一套流程，但机器密钥是「指纹派生 KEK 加密的软件密钥」。
		dimg_log.notice("image layer: %s", path);

		u8 tag[TAG_SIZE];
		if (!read_exact(file, TAG_OFFSET, tag, sizeof(tag)))
		{
			dimg_log.error("image header unreadable: %s", path);
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
				dimg_log.notice("activation data: %s", candidate);
				break;
			}
			dimg_log.error("activation %s: %s", candidate, lic.error);
		}

		if (!lic.ok)
		{
			dimg_log.error("no activation data found (searched next to the image, the working dir, %s and the flatpak config dir) — "
				"run rpcs3z --activate first", config_dir());
			return fs::file{};
		}

		if (tag[9] != PROFILE_PLATFORM)
		{
			dimg_log.error("this image is not the Steam Deck build (E8: image platform %u, this build expects %u)",
				unsigned(tag[9]), unsigned(PROFILE_PLATFORM));
			return fs::file{};
		}

		if (std::memcmp(lic.tag.data(), tag, TAG_SIZE) != 0)
		{
			dimg_log.error("activation data does not match this image (E4)");
			return fs::file{};
		}

		machine_key mk;
		std::string err;
		if (!machine_key_open(mk, false, err))
		{
			dimg_log.error("device key unavailable (E5): %s", err.c_str());
			return fs::file{};
		}

		u8 k_iso[32];
		u8 iv[16];
		if (!unseal_iso_keys(lic, mk, k_iso, iv))
		{
			dimg_log.error("activation does not open on this device (E6, %s)", config_dir());
			return fs::file{};
		}

		const u64 size = file.size();
		dimg_log.notice("activation OK (%02x%02x%02x%02x…), decrypting on demand",
			unsigned(lic.recipient[0]), unsigned(lic.recipient[1]), unsigned(lic.recipient[2]), unsigned(lic.recipient[3]));

		fs::file out(std::unique_ptr<fs::file_base>(new lock_file(std::move(file), size, k_iso, iv)));
		secure_zero(k_iso, sizeof(k_iso));
		secure_zero(iv, sizeof(iv));
		return out;
#endif
	}

	bool handle_command_line(int argc, char** argv)
	{
		bool do_activate = false;
		bool do_diagnose = false;
		bool do_reset = false;

		for (int i = 1; i < argc; i++)
		{
			const std::string arg = argv[i] ? argv[i] : "";

			// Accept --activate / --diag / --reset-key (also -xxx, /xxx and bare xxx, any case).
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

			if (key == "activate")
			{
				do_activate = true;
			}
			else if (key == "diag")
			{
				do_diagnose = true;
			}
			else if (key == "reset-key")
			{
				do_reset = true;
			}
			else if (!arg.empty() && (arg[0] == '-' || arg[0] == '/') &&
				(key.find("activ") != std::string::npos || key.find("diag") != std::string::npos))
			{
				dimg_log.error("unrecognized argument '%s' (expected --activate or --diag)", arg);
			}
		}

		if (!do_activate && !do_diagnose && !do_reset)
		{
			return false;
		}

#ifdef _WIN32
		std::string reset_note;

		if (do_reset)
		{
			std::string key_note;
			machine_key_delete(key_note);
			reset_note = "机器密钥：" + key_note;

			// Remove stale activation files (best effort).
			const std::string cfg = config_dir();
			const std::string to_remove[] = {
				cfg + "license.bin", cfg + "machine.key", "request.bin",
				"activate.txt", "diag.txt", "code.txt", "status.txt",
			};

			for (const std::string& path : to_remove)
			{
				if (DeleteFileW(to_wide(path).c_str()))
				{
					reset_note += "\nremoved: " + path;
				}
			}

			do_activate = true;   // regenerate a fresh request.bin right away
		}

		machine_key mk;
		std::string err;
		const bool have_key = machine_key_open(mk, do_activate, err);
		const std::string info = machine_info_text();

		if (do_activate)
		{
			std::string act;

			addf(act, "=== 第一步：生成申请码 ===\n\n");
			if (!reset_note.empty())
			{
				addf(act, "重置结果     : %s\n\n", reset_note.c_str());
			}

			if (!have_key)
			{
				addf(act, "失败：%s\n", err.c_str());

				std::string wstat;
				write_text_file("activate.txt", info + "\n" + act, wstat);
				print_text(act);
				return true;
			}

			u8 request[REQ_LEN] = {};
			magic_put(request, REQUEST_MAGIC_MASKED, 4);
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

			// Base32 text covers only the 274 B core: the chat fallback stays pasteable.
			const std::string code = base32_grouped(request, sizeof(request));
			const diagnose_result diag = build_diagnose_text(mk, have_key, err);

			addf(act, "密钥类型     : %s\n", mk.used_tpm ? "TPM（密钥不可导出）" : "软件 KSP（密钥不可导出）");
			if (!mk.used_tpm && !mk.note.empty())
			{
				addf(act, "TPM 说明     : %s\n", mk.note.c_str());
			}
			addf(act, "密钥目录     : %s\n", config_dir().c_str());
			addf(act, "激活码       :\n%s\n", code.c_str());
			addf(act, "\n请把 request.bin 这个文件发给作者，作者会回给你 license.bin。\n");

			const std::string bundle = info + "\n" + act + "\n" + diag.text
				+ "\n激活判定     : " + (diag.active ? "已激活" : "未激活") + "（" + diag.reason + "）\n";

			// request.bin carries the whole bundle (zlib) so the signing side keeps the full picture.
			const std::string blob = build_request_with_report(request, sizeof(request), bundle);
			std::string status;
			const std::string req_path = write_output("request.bin", blob.data(), blob.size(), status);

			std::string wstat;
			write_text_file("code.txt", code + "\n", wstat);
			write_text_file("activate.txt", bundle, wstat);

			dimg_log.notice("activation request: %s (%u B, report %u B compressed)",
				req_path.empty() ? status.c_str() : req_path.c_str(), unsigned(blob.size()), unsigned(bundle.size()));

			print_text("激活码：\n" + code + "\n");
			return true;
		}

		const diagnose_result res = build_diagnose_text(mk, have_key, err);

		std::string status_text;
		addf(status_text, "status=%s\n", res.active ? "ACTIVE" : "INACTIVE");
		addf(status_text, "激活状态：%s\n", res.active ? "已激活" : "未激活");
		addf(status_text, "说明：%s\n", res.reason.c_str());

		std::string wstat;
		write_text_file("status.txt", status_text, wstat);
		write_text_file("diag.txt", info + "\n" + res.text, wstat);

		dimg_log.notice("license status: %s (%s)", res.active ? "ACTIVE" : "INACTIVE", res.reason.c_str());

		print_text(std::string("激活状态：") + (res.active ? "已激活" : "未激活") + "\n");
		return true;
#else
		// POSIX：/bin/sh 下的激活 / 诊断 / 重置（不需要 .bat，输出直写配置目录）
		if (!do_activate && !do_diagnose && !do_reset)
		{
			return false;
		}

		const std::string info = machine_info_text();

		if (do_reset)
		{
			std::string note;
			const bool gone = machine_key_delete(note);
			print_text("机器密钥：" + note + "\n");
			if (!gone)
			{
				dimg_log.error("reset: %s", note.c_str());
				return true;
			}
			std::string wstat;
			write_text_file("reset.txt", info + "\n重置完成：已删除机器密钥。请重新运行 --activate 并重新签发 license。\n", wstat);
			return true;
		}

		machine_key mk;
		std::string err;
		const bool have_key = machine_key_open(mk, do_activate, err);

		if (do_activate)
		{
			std::string body = "=== 第一步：生成申请码 ===\n\n";
			if (!have_key)
			{
				addf(body, "生成机器密钥失败：%s\n", err.c_str());
				std::string wstat;
				write_text_file("activate.txt", info + "\n" + body, wstat);
				print_text(body);
				dimg_log.error("activate: %s", err.c_str());
				return true;
			}

			const u64 hwid = hwid_hash8();
			u8 core[REQ_LEN] = {};
			magic_put(core, REQUEST_MAGIC_MASKED, sizeof(REQUEST_MAGIC_MASKED));
			core[4] = static_cast<u8>(REQ_VER);
			std::memcpy(core + 8, mk.modulus, RSA_BYTES);
			for (int i = 0; i < 8; i++)
			{
				core[8 + RSA_BYTES + i] = static_cast<u8>((hwid >> ((7 - i) * 8)) & 0xFF);
			}
			const u16 crc = crc16(core, REQ_LEN - 2);
			core[REQ_LEN - 2] = static_cast<u8>((crc >> 8) & 0xFF);
			core[REQ_LEN - 1] = static_cast<u8>(crc & 0xFF);

			const std::string blob = build_request_with_report(core, REQ_LEN, info + "\n" + body);
			std::string werr;
			const std::string req_path = config_dir() + "request.bin";
			if (!write_file_bytes(req_path, blob.data(), blob.size(), werr))
			{
				addf(body, "写不进 %s：%s\n", req_path.c_str(), werr.c_str());
				print_text(body);
				return true;
			}

			const std::string code = base32_grouped(core, REQ_LEN);
			std::string wstat;
			write_text_file("code.txt", code + "\n", wstat);
			write_text_file("activate.txt", info + "\n" + body +
				"申请码文件   : " + req_path + "\n激活码       : " + code + "\n", wstat);

			addf(body, "申请码文件   : %s（%u B）\n", req_path.c_str(), unsigned(blob.size()));
			body += "激活码       : " + code + "\n";
			body += "\n把这个文件（或上面这串）发给作者，拿到 license.bin 后放到：\n  " + config_dir() + "license.bin\n";
			print_text(body);
			dimg_log.notice("activation request written (%u B)", unsigned(blob.size()));
			return true;
		}

		// --diag
		const diagnose_result res = build_diagnose_text(mk, have_key, err);

		std::string status_text;
		addf(status_text, "status=%s\n", res.active ? "ACTIVE" : "INACTIVE");
		addf(status_text, "激活状态：%s\n", res.active ? "已激活" : "未激活");
		addf(status_text, "说明：%s\n", res.reason.c_str());
		addf(status_text, "授权文件：%s\n", (config_dir() + "license.bin").c_str());

		std::string wstat;
		const std::string spath = write_text_file("status.txt", status_text, wstat);
		const std::string dpath = write_text_file("diag.txt", info + "\n" + res.text, wstat);

		dimg_log.notice("license status: %s (%s)", res.active ? "ACTIVE" : "INACTIVE", res.reason.c_str());

		std::string shown = std::string("激活状态：") + (res.active ? "已激活" : "未激活") + "\n";
		shown += "说明：" + res.reason + "\n";
		if (!spath.empty()) shown += "状态文件：" + spath + "\n";
		if (!dpath.empty()) shown += "详细报告：" + dpath + "\n";
		print_text(shown);
		return true;
#endif
	}
}
