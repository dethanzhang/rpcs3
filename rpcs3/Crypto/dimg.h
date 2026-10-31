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
// Windows 定制版用 CNG 持久化密钥（TPM 优先）；Steam Deck/Linux（POSIX 分支）用指纹派生 KEK 加密的软件密钥。
//
// 多 license store（Windows 定制版 + Steam Deck POSIX 分支共用）：
//   <config>/dimg/licenses/<licid>.lic     licid = sha256(4096 B tag)[:16]（按内容算）
// 一个 exe/一份安装可以同时装多份授权（不同 tag 共存）；打开某张盘时按盘上的 tag 选对应那份。
// **legacy 仍然兼容**：ISO 目录 license.bin、cwd license.bin、<config>/dimg/license.bin、
// Deck flatpak 路径照旧读取；store 优先，legacy 兜底。

#include <string>
#include <vector>

#include "Utilities/File.h"

namespace dimg
{
	// Returns true if the file carries the image tag (checked at 0x1000). Takes a mutable ref (read_at is non-const).
	bool is_locked(fs::file& file);

	// Opens `path`. If the image is locked, returns a decrypting wrapper
	// (invalid file + log error when the activation data is missing/invalid).
	fs::file open_maybe_locked(const std::string& path, bs_t<fs::open_mode> mode);

	// ---------------------------------------------------------------- 多 license store
	// 一次可以装多份授权（不同 tag 共存），文件名为 sha256(4096B tag)[:16]：
	//   <config>/dimg/licenses/<licid>.lic
	// 打开某张盘时按「盘上的 tag」选对应那份，而不是「第一个能验签的」。
	struct license_entry
	{
		std::string licid;        // sha256(4096B tag)[:16]（内容算，不看文件名）
		u8 platform_code = 0;
		std::string platform;     // "Windows" / "Steam Deck" / "Android"
		std::string recipient;    // hex 32
		std::string hwid;         // hex 16
		std::string tag_sha256;   // hex 64
		std::string file;         // 完整路径
		bool signature_ok = false;
		bool opens_here = false;  // 本机私钥能解出 K_iso
		std::string error;        // E1/E2/E5/E6/… 人类可读
	};

	// 列出 store 里所有授权（验签失败的也列出来，error 说明原因；按 licid 排序）。
	std::vector<license_entry> list_licenses();

	// 导入 license 内容：平台档检查 → 验签 → 试开（确认是发给本机的）→ 才落盘。
	// 落盘位置是 store：<config>/dimg/licenses/<licid>.lic（同一 licid 覆盖写，原子替换）。
	// 不写 legacy license.bin。
	bool import_license(const std::vector<u8>& blob, std::string& err);
	bool import_license_file(const std::string& path, std::string& err);

	// Handles --activate / --diag / --reset-key / --import-license / --list-licenses.
	// --import-license <file>（或 --import-license=<file>）的输出契约：stdout 打一行结果，
	// 并且每次都写结果文件 import.txt（Windows: exe 目录 / GBK+CRLF，POSIX: config 目录）：
	//   成功：首行 "OK <licid> <platform>"，次行 "已导入：<licid>（<platform>）"
	//   失败：首行 "FAIL <中文原因>"（单行，无裸换行），次行 "导入失败，见上面的原因。"
	// 缺路径时也写 import.txt，首行为 "FAIL 缺少授权文件路径（--import-license <file>）"。
	// .bat 用 `findstr /b /c:"OK " import.txt` 判断成功，不依赖控制台。
	// Returns true when handled.
	bool handle_command_line(int argc, char** argv);
}
