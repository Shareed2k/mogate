#ifndef MG_SIP_DARWIN_H
#define MG_SIP_DARWIN_H

// SIP detection + injectable-slice selection for the injector dylib. This is a
// C port of pkg/local/sip_darwin.go (needsSIPPatch / chooseSlice); the two must
// agree byte-for-byte on which slice is chosen (Task E1 enforces this with
// golden vectors). Everything here is guarded by __APPLE__: the injector also
// builds on linux, which has no System Integrity Protection.
//
// The whole file is included by BOTH injector/main.go's cgo comment block (so
// the built dylib carries these functions) and the darwin cgo test bridge (so
// the test can exercise them). Those are two separate translation units, so all
// functions are `static`: each TU gets its own copy and there is no
// duplicate-symbol link error.

#ifdef __APPLE__

#include <errno.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Constants mirror pkg/local/sip_darwin.go exactly. They are re-declared here
// rather than taken from the SDK headers so the C and Go ports are provably the
// same values.

// SF_RESTRICTED: the file flag (stat.st_flags) that marks a SIP-protected file.
#define MG_SIP_SF_RESTRICTED 0x00080000u

// cpu type/subtype (mach/machine.h) used to pick a loadable slice.
#define MG_SIP_CPU_TYPE_X86_64 0x01000007u
#define MG_SIP_CPU_TYPE_ARM64 0x0100000cu
#define MG_SIP_CPU_SUBTYPE_ARM64E 2u

// Mach-O / fat magics (read big-endian for fat, host order for thin).
#define MG_SIP_FAT_MAGIC 0xcafebabeu
#define MG_SIP_FAT_MAGIC_64 0xcafebabfu
#define MG_SIP_MH_MAGIC 0xfeedfaceu
#define MG_SIP_MH_MAGIC_64 0xfeedfacfu

// Code-signing constants (cs_blobs.h). All CS fields are big-endian.
#define MG_SIP_CS_MAGIC_EMBEDDED 0xfade0cc0u
#define MG_SIP_CS_MAGIC_CODEDIR 0xfade0c02u
#define MG_SIP_CS_SLOT_CODEDIR 0u
#define MG_SIP_CS_SLOT_ENTITLEMENTS 5u
#define MG_SIP_CS_RESTRICT 0x0000800u
#define MG_SIP_CS_RUNTIME 0x00010000u
#define MG_SIP_CS_BLOB_INDEX_SIZE 8u
#define MG_SIP_CS_MAX_BLOB_COUNT (1u << 16)

// LC_CODE_SIGNATURE load command; its body is a linkedit_data_command
// { cmd, cmdsize, dataoff, datasize }, all uint32 in the slice's byte order.
#define MG_SIP_LC_CODE_SIGNATURE 0x1du

// The entitlement that already lets dyld honor DYLD_* env vars, so a binary
// carrying it is not treated as needing a patch.
static const char MG_SIP_ENT_ALLOW_DYLD[] =
	"com.apple.security.cs.allow-dyld-environment-variables";

static uint32_t mg_sip_be32(const uint8_t *p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t mg_sip_le32(const uint8_t *p) {
	return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
		((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static uint32_t mg_sip_rd32(const uint8_t *p, int big_endian) {
	return big_endian ? mg_sip_be32(p) : mg_sip_le32(p);
}

// mg_sip_slice_in_bounds validates [offset, offset+size) falls within a
// total-byte buffer, computing in 64-bit so offset+size cannot wrap. Mirrors
// extractFatSlice's guard.
static int mg_sip_slice_in_bounds(uint64_t offset, uint64_t size, uint64_t total) {
	uint64_t end = offset + size;
	if (end < offset) {
		return 0;
	}
	if (end > total) {
		return 0;
	}
	return 1;
}

// mg_sip_is_plain_arm64 reports whether cputype/subtype identify an arm64 slice
// that is not arm64e. dyld enforces pointer authentication on arm64e and will
// not relax DYLD_INSERT_LIBRARIES there, so such slices are not injectable.
static int mg_sip_is_plain_arm64(uint32_t cputype, uint32_t subtype) {
	return cputype == MG_SIP_CPU_TYPE_ARM64 &&
		(subtype & 0xffu) != MG_SIP_CPU_SUBTYPE_ARM64E;
}

// mg_sip_is_macho reports whether data begins with a thin or fat Mach-O magic.
// Mirrors isMachO: fat/fat64 are big-endian; thin may be either byte order.
static int mg_sip_is_macho(const uint8_t *data, size_t len) {
	if (len < 4) {
		return 0;
	}
	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_FAT_MAGIC || be == MG_SIP_FAT_MAGIC_64) {
		return 1;
	}
	uint32_t le = mg_sip_le32(data);
	if (le == MG_SIP_MH_MAGIC || le == MG_SIP_MH_MAGIC_64) {
		return 1;
	}
	if (be == MG_SIP_MH_MAGIC || be == MG_SIP_MH_MAGIC_64) {
		return 1;
	}
	return 0;
}

// mg_sip_thin_header classifies a thin Mach-O header: it sets *big_endian to the
// slice's byte order and *is64 to whether it is a 64-bit (mach_header_64) image,
// returning 1 on a recognized thin magic and 0 otherwise.
static int mg_sip_thin_header(const uint8_t *data, size_t len, int *big_endian, int *is64) {
	if (len < 4) {
		return 0;
	}
	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_MH_MAGIC || be == MG_SIP_MH_MAGIC_64) {
		*big_endian = 1;
		*is64 = (be == MG_SIP_MH_MAGIC_64);
		return 1;
	}
	uint32_t le = mg_sip_le32(data);
	if (le == MG_SIP_MH_MAGIC || le == MG_SIP_MH_MAGIC_64) {
		*big_endian = 0;
		*is64 = (le == MG_SIP_MH_MAGIC_64);
		return 1;
	}
	return 0;
}

// mg_sip_thin_header_size returns the byte size of a thin Mach-O header:
// mach_header (28) or mach_header_64 (32). Load commands follow it.
static size_t mg_sip_thin_header_size(int is64) {
	return is64 ? 32u : 28u;
}

// mg_sip_choose_slice selects a slice of a (possibly fat) Mach-O that dyld can
// load with DYLD_INSERT_LIBRARIES honored: a plain-arm64 slice is preferred
// (native injector), else x86_64 under Rosetta, else none. On success it sets
// *out_off/*out_size to the chosen slice's byte range within data, *out_is_rosetta
// to 1 for an x86_64/Rosetta slice or 0 for native, and returns a pointer into
// data at the slice start (which the caller must NOT free). It returns NULL on
// an arm64e-only binary (ErrNoInjectableSlice), a malformed/out-of-bounds
// header, or a bad argument. Mirrors chooseSlice.
static char *mg_sip_choose_slice(const uint8_t *data, size_t len,
	size_t *out_off, size_t *out_size, int *out_is_rosetta) {
	if (!data || !out_off || !out_size || !out_is_rosetta || len < 4) {
		return NULL;
	}

	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_FAT_MAGIC) {
		// 32-bit fat header: { magic, nfat_arch } then nfat_arch fat_arch
		// entries { cputype, cpusubtype, offset, size, align }, each 20 bytes,
		// all big-endian. (A fat64 header is treated as non-fat, like Go, and
		// falls through to the thin path where it fails to parse -> NULL.)
		if (len < 8) {
			return NULL;
		}
		uint32_t nfat = mg_sip_be32(data + 4);
		size_t x86_off = 0;
		size_t x86_size = 0;
		int have_x86 = 0;
		for (uint32_t i = 0; i < nfat; i++) {
			size_t entry = 8 + (size_t)i * 20u;
			if (entry + 20u > len) {
				return NULL;
			}
			uint32_t cputype = mg_sip_be32(data + entry);
			uint32_t subtype = mg_sip_be32(data + entry + 4);
			uint32_t offset = mg_sip_be32(data + entry + 8);
			uint32_t size = mg_sip_be32(data + entry + 12);
			if (mg_sip_is_plain_arm64(cputype, subtype)) {
				if (!mg_sip_slice_in_bounds(offset, size, len)) {
					return NULL;
				}
				*out_off = offset;
				*out_size = size;
				*out_is_rosetta = 0;
				return (char *)(uintptr_t)(data + offset);
			}
			if (cputype == MG_SIP_CPU_TYPE_X86_64 && !have_x86) {
				have_x86 = 1;
				x86_off = offset;
				x86_size = size;
			}
		}
		if (have_x86) {
			if (!mg_sip_slice_in_bounds(x86_off, x86_size, len)) {
				return NULL;
			}
			*out_off = x86_off;
			*out_size = x86_size;
			*out_is_rosetta = 1;
			return (char *)(uintptr_t)(data + x86_off);
		}
		return NULL;
	}

	// Thin Mach-O: choose the whole file if its single arch is injectable.
	int big_endian = 0;
	int is64 = 0;
	if (!mg_sip_thin_header(data, len, &big_endian, &is64)) {
		return NULL;
	}
	if (len < mg_sip_thin_header_size(is64)) {
		return NULL;
	}
	uint32_t cputype = mg_sip_rd32(data + 4, big_endian);
	uint32_t subtype = mg_sip_rd32(data + 8, big_endian);
	if (mg_sip_is_plain_arm64(cputype, subtype)) {
		*out_off = 0;
		*out_size = len;
		*out_is_rosetta = 0;
		return (char *)(uintptr_t)data;
	}
	if (cputype == MG_SIP_CPU_TYPE_X86_64) {
		*out_off = 0;
		*out_size = len;
		*out_is_rosetta = 1;
		return (char *)(uintptr_t)data;
	}
	return NULL;
}

// mg_sip_find_lc_code_sig scans one thin Mach-O slice's load commands for
// LC_CODE_SIGNATURE, returning 1 and setting *out_dataoff/*out_datasize (both
// relative to the slice's start) when found, 0 when the slice parses but has no
// signature, and -1 on a malformed/truncated header. Mirrors codeSignatureLoad.
static int mg_sip_find_lc_code_sig(const uint8_t *slice, size_t slice_len,
	uint32_t *out_dataoff, uint32_t *out_datasize) {
	int big_endian = 0;
	int is64 = 0;
	if (!mg_sip_thin_header(slice, slice_len, &big_endian, &is64)) {
		return -1;
	}
	size_t header = mg_sip_thin_header_size(is64);
	if (slice_len < header) {
		return -1;
	}
	uint32_t ncmds = mg_sip_rd32(slice + 16, big_endian);
	size_t pos = header;
	for (uint32_t i = 0; i < ncmds; i++) {
		if (pos + 8u > slice_len) {
			return -1;
		}
		uint32_t cmd = mg_sip_rd32(slice + pos, big_endian);
		uint32_t cmdsize = mg_sip_rd32(slice + pos + 4, big_endian);
		if (cmdsize < 8u || pos + cmdsize > slice_len) {
			return -1;
		}
		if (cmd == MG_SIP_LC_CODE_SIGNATURE) {
			if (cmdsize < 16u) {
				return -1;
			}
			*out_dataoff = mg_sip_rd32(slice + pos + 8, big_endian);
			*out_datasize = mg_sip_rd32(slice + pos + 12, big_endian);
			return 1;
		}
		pos += cmdsize;
	}
	return 0;
}

// mg_sip_first_code_signature returns the absolute file offset and size of the
// code-signature blob of the first slice that carries one: 1 and sets
// *out_off/*out_size when found, 0 when no slice has a signature, -1 on a
// malformed image. For a fat binary the offset is arch.offset + the slice's own
// dataoff (dataoff is slice-relative). Mirrors firstCodeSignature.
static int mg_sip_first_code_signature(const uint8_t *data, size_t len,
	uint32_t *out_off, uint32_t *out_size) {
	if (len < 4) {
		return -1;
	}
	uint32_t be = mg_sip_be32(data);
	if (be == MG_SIP_FAT_MAGIC) {
		if (len < 8) {
			return -1;
		}
		uint32_t nfat = mg_sip_be32(data + 4);
		for (uint32_t i = 0; i < nfat; i++) {
			size_t entry = 8 + (size_t)i * 20u;
			if (entry + 20u > len) {
				return -1;
			}
			uint32_t offset = mg_sip_be32(data + entry + 8);
			uint32_t size = mg_sip_be32(data + entry + 12);
			if (!mg_sip_slice_in_bounds(offset, size, len)) {
				return -1;
			}
			uint32_t dataoff = 0;
			uint32_t datasize = 0;
			int rc = mg_sip_find_lc_code_sig(data + offset, size, &dataoff, &datasize);
			if (rc < 0) {
				return -1;
			}
			if (rc == 1) {
				uint64_t absolute = (uint64_t)offset + (uint64_t)dataoff;
				if (absolute > 0xffffffffULL) {
					return -1;
				}
				*out_off = (uint32_t)absolute;
				*out_size = datasize;
				return 1;
			}
		}
		return 0;
	}

	int big_endian = 0;
	int is64 = 0;
	if (!mg_sip_thin_header(data, len, &big_endian, &is64)) {
		return -1;
	}
	uint32_t dataoff = 0;
	uint32_t datasize = 0;
	int rc = mg_sip_find_lc_code_sig(data, len, &dataoff, &datasize);
	if (rc < 0) {
		return -1;
	}
	if (rc == 0) {
		return 0;
	}
	*out_off = dataoff;
	*out_size = datasize;
	return 1;
}

// mg_sip_contains reports whether haystack contains needle (a raw byte search;
// needle need not be NUL-terminated in haystack). Mirrors bytes.Contains.
static int mg_sip_contains(const uint8_t *haystack, size_t haystack_len,
	const char *needle, size_t needle_len) {
	if (needle_len == 0) {
		return 1;
	}
	if (haystack_len < needle_len) {
		return 0;
	}
	for (size_t i = 0; i + needle_len <= haystack_len; i++) {
		if (memcmp(haystack + i, needle, needle_len) == 0) {
			return 1;
		}
	}
	return 0;
}

// mg_sip_code_directory_flags reads the big-endian flags field (offset 12) of a
// CodeDirectory blob (magic csMagicCodeDirectory). Returns 0 on success, -1 on a
// too-small blob or wrong magic. Mirrors codeDirectoryFlags.
static int mg_sip_code_directory_flags(const uint8_t *blob, size_t len, uint32_t *out_flags) {
	if (len < 16) {
		return -1;
	}
	if (mg_sip_be32(blob) != MG_SIP_CS_MAGIC_CODEDIR) {
		return -1;
	}
	*out_flags = mg_sip_be32(blob + 12);
	return 0;
}

// mg_sip_parse_superblob walks a CS SuperBlob's index (magic
// csMagicEmbeddedSignature), setting *out_flags to the CodeDirectory flags and
// *out_has_dyld to whether the entitlements blob carries the allow-dyld
// entitlement. Returns 0 on success, -1 on any malformed field. All CS fields
// are big-endian. Mirrors parseCSSuperBlob.
static int mg_sip_parse_superblob(const uint8_t *blob, size_t blob_len,
	uint32_t *out_flags, int *out_has_dyld) {
	*out_flags = 0;
	*out_has_dyld = 0;
	if (blob_len < 12) {
		return -1;
	}
	if (mg_sip_be32(blob) != MG_SIP_CS_MAGIC_EMBEDDED) {
		return -1;
	}
	uint32_t count = mg_sip_be32(blob + 8);
	if (count > MG_SIP_CS_MAX_BLOB_COUNT) {
		return -1;
	}
	for (uint32_t i = 0; i < count; i++) {
		size_t entry_off = 12 + (size_t)i * MG_SIP_CS_BLOB_INDEX_SIZE;
		if (entry_off + MG_SIP_CS_BLOB_INDEX_SIZE > blob_len) {
			return -1;
		}
		uint32_t slot_type = mg_sip_be32(blob + entry_off);
		uint32_t slot_offset = mg_sip_be32(blob + entry_off + 4);
		if ((size_t)slot_offset > blob_len) {
			return -1;
		}
		if (slot_type == MG_SIP_CS_SLOT_CODEDIR) {
			uint32_t flags = 0;
			if (mg_sip_code_directory_flags(blob + slot_offset, blob_len - slot_offset, &flags) < 0) {
				return -1;
			}
			*out_flags = flags;
		} else if (slot_type == MG_SIP_CS_SLOT_ENTITLEMENTS) {
			if (mg_sip_contains(blob + slot_offset, blob_len - slot_offset,
				MG_SIP_ENT_ALLOW_DYLD, sizeof(MG_SIP_ENT_ALLOW_DYLD) - 1)) {
				*out_has_dyld = 1;
			}
		}
	}
	return 0;
}

// mg_sip_code_signature_flags returns the CodeDirectory flags of the first
// signed slice and whether the allow-dyld entitlement is present. Returns 0 on
// success (with flags 0 / has_dyld 0 for an unsigned binary) and -1 on a
// malformed image or out-of-bounds signature. Mirrors codeSignatureFlags.
static int mg_sip_code_signature_flags(const uint8_t *data, size_t len,
	uint32_t *out_flags, int *out_has_dyld) {
	*out_flags = 0;
	*out_has_dyld = 0;
	uint32_t sig_off = 0;
	uint32_t sig_size = 0;
	int rc = mg_sip_first_code_signature(data, len, &sig_off, &sig_size);
	if (rc < 0) {
		return -1;
	}
	if (rc == 0) {
		return 0;
	}
	if ((uint64_t)sig_off + (uint64_t)sig_size > (uint64_t)len) {
		return -1;
	}
	return mg_sip_parse_superblob(data + sig_off, sig_size, out_flags, out_has_dyld);
}

// mg_sip_read_file reads the whole file at path into a freshly malloc'd buffer,
// setting *out_len to its size, or returns NULL on any error. The caller owns
// and must free the buffer.
static uint8_t *mg_sip_read_file(const char *path, size_t *out_len) {
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}
	struct stat st;
	if (fstat(fd, &st) != 0 || st.st_size < 0) {
		close(fd);
		return NULL;
	}
	size_t size = (size_t)st.st_size;
	uint8_t *buffer = (uint8_t *)malloc(size ? size : 1);
	if (!buffer) {
		close(fd);
		return NULL;
	}
	size_t got = 0;
	while (got < size) {
		ssize_t n = read(fd, buffer + got, size - got);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			free(buffer);
			close(fd);
			return NULL;
		}
		if (n == 0) {
			break; // shrunk under us; report what we read
		}
		got += (size_t)n;
	}
	close(fd);
	*out_len = got;
	return buffer;
}

// mg_sip_needs_patch reports whether path is a restricted Mach-O whose execution
// would ignore DYLD_INSERT_LIBRARIES: 1 restricted, 0 not (including scripts and
// non-Mach-O files), -1 on error. Mirrors needsSIPPatch: a binary is restricted
// if it carries SF_RESTRICTED or a CS RESTRICT/RUNTIME flag, unless it already
// holds the allow-dyld entitlement.
static int mg_sip_needs_patch(const char *path) {
	if (!path) {
		return -1;
	}
	struct stat st;
	if (stat(path, &st) != 0) {
		return -1;
	}
	int restricted_flag = (st.st_flags & MG_SIP_SF_RESTRICTED) != 0;

	size_t len = 0;
	uint8_t *data = mg_sip_read_file(path, &len);
	if (!data) {
		return -1;
	}
	if (!mg_sip_is_macho(data, len)) {
		free(data);
		return 0;
	}
	uint32_t cs_flags = 0;
	int has_dyld = 0;
	int rc = mg_sip_code_signature_flags(data, len, &cs_flags, &has_dyld);
	free(data);
	if (rc < 0) {
		return -1;
	}
	int restricted = restricted_flag ||
		(cs_flags & (MG_SIP_CS_RESTRICT | MG_SIP_CS_RUNTIME)) != 0;
	return (restricted && !has_dyld) ? 1 : 0;
}

#endif // __APPLE__

#endif // MG_SIP_DARWIN_H
