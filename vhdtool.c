/*
   VHD manipulation tool (MSVC compatible single-file port)

   Original Copyright (C) 2011 Andrei Warkentin <andreiw@msalumni.com>
   Ported for MSVC by ChatGPT (2025)

   Build (Visual Studio Developer Command Prompt):
     cl /std:c11 /O2 /W3 /D_CRT_SECURE_NO_WARNINGS vhdtool2_msvc.c Rpcrt4.lib
*/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <rpc.h>   // UUID

#pragma comment(lib, "Rpcrt4.lib")

/* ---- endian helpers ---- */
#define htobe16(x) _byteswap_ushort((uint16_t)(x))
#define htobe32(x) _byteswap_ulong((uint32_t)(x))
#define htobe64(x) _byteswap_uint64((uint64_t)(x))
#define be16toh(x) _byteswap_ushort((uint16_t)(x))
#define be32toh(x) _byteswap_ulong((uint32_t)(x))
#define be64toh(x) _byteswap_uint64((uint64_t)(x))

/* types/posix shims */
typedef __int64 off64_t;
#define lseek64   _lseeki64
#define read      _read
#define write     _write
#define open      _open
#define close     _close
#define fstat     _fstat64
#define fsync     _commit
#define unlink    _unlink
#define O_EXCL    _O_EXCL
#define O_CREAT   _O_CREAT
#define O_RDWR    _O_RDWR
#define O_RDONLY  _O_RDONLY
#ifndef S_IRUSR
#  define S_IRUSR _S_IREAD
#  define S_IWUSR _S_IWRITE
#endif

/* cookies & constants */
#define COOKIE(x)           (*(uint64_t *)(x))
#define COOKIE32(x)         (*(uint32_t *)(x))
#define FOOTER_FEAT_RSVD    (2)
#define VHD_VERSION_1       (0x00010000UL)
#define FOOTER_DOFF_FIXED   (0xFFFFFFFFFFFFFFFFULL)
#define DYN_DOFF_DYN        (0xFFFFFFFFFFFFFFFFULL)
#define SECONDS_OFFSET      946684800
#define FOOTER_TYPE_FIXED   (2)
#define FOOTER_TYPE_DYN     (3)
#define FOOTER_TYPE_DIFF    (4)
#define SEC_SHIFT           (9)
#define SEC_SZ              (1 << SEC_SHIFT)
#define SEC_MASK            (SEC_SZ - 1)
#define round_up(what, on)  ((((what) + (on) - 1) / (on)) * (on))
#define DYN_BLOCK_SZ        0x200000
#define BAT_ENTRY_EMPTY     0xFFFFFFFF

/* file-local flags */
#define OPEN_RAW_OK (1u << 1)
#define OPEN_RW     (1u << 2)
#define OPEN_CREAT  (1u << 3)
#define COMPAT_SIZE (1u << 4)

#pragma pack(push,1)
struct vhd_id { uint32_t f1; uint16_t f2; uint16_t f3; uint8_t  f4[8]; };
struct vhd_chs { uint16_t c; uint8_t  h; uint8_t  s; };
struct vhd_footer {
    uint64_t cookie;
    uint32_t features;
    uint32_t file_format_ver;
    uint64_t data_offset;
    uint32_t time_stamp;
    uint32_t creator_app;
    uint32_t creator_ver;
    uint32_t creator_os;
    uint64_t original_size;
    uint64_t current_size;
    struct vhd_chs disk_geometry;
    uint32_t disk_type;
    uint32_t checksum;
    struct vhd_id vhd_id;
    uint8_t  saved_state;
    uint8_t  reserved[427];
};
struct vhd_ploc { uint32_t code, sectors, length, reserved; uint64_t offset; };
struct vhd_dyn {
    uint64_t cookie;
    uint64_t data_offset;
    uint64_t table_offset;
    uint32_t header_version;
    uint32_t max_tab_entries;
    uint32_t block_size;
    uint32_t checksum;
    struct vhd_id parent;
    uint32_t parent_time_stamp;
    uint32_t reserved0;
    uint8_t  parent_utf16[512];
    struct vhd_ploc pe[8];
    uint8_t  reserved1[256];
};
#pragma pack(pop)

typedef uint32_t vhd_batent;

struct vhd;
typedef int (*op_read_t)(struct vhd*, void*, off64_t, size_t);
typedef int (*op_write_t)(struct vhd*, void*, off64_t, size_t);

struct vhd {
    struct vhd_footer footer;
    struct vhd_dyn    dyn;
    char     uuid_str[37];
    char* name;
    off64_t  size;
    off64_t  offset;
    int      fd;
    off64_t  file_size;
    uint32_t type;
    unsigned flags;
    op_read_t  read;
    op_write_t write;
};

/* -------- getopt minimal -------- */
int opterr = 1, optind = 1, optopt, optreset; char* optarg;
static int getopt_ms(int nargc, char* const nargv[], const char* ostr)
{
    static char* place = ""; const char* oli;
    if (optreset || *place == '\0') {
        optreset = 0;
        if (optind >= nargc || *(place = nargv[optind]) != '-') return -1;
        if (!*++place) return -1; /* '-' */
        if (*place == '-') { optind++; return -1; } /* "--" */
    }
    if ((optopt = (unsigned char)*place++) == ':' || !(oli = strchr(ostr, optopt))) {
        if (!*place) optind++;
        return '?';
    }
    if (*++oli != ':') { optarg = NULL; if (!*place) optind++; }
    else {
        if (*place) optarg = place; else if (nargc <= ++optind) { place = ""; return '?'; }
        else optarg = nargv[optind];
        place = ""; optind++;
    }
    return optopt;
}
#define getopt getopt_ms

/* -------- helpers -------- */
static void uuid_make(struct vhd_id* out_be, char out_str[37])
{
    UUID u; UuidCreate(&u);
    RPC_CSTR s = NULL; UuidToStringA(&u, &s);
    if (s) {
        strncpy(out_str, (const char*)s, 36); out_str[36] = '\0';
        RpcStringFreeA(&s);
    }
    else {
        strcpy(out_str, "00000000-0000-0000-0000-000000000000");
    }
    out_be->f1 = htobe32(u.Data1);
    out_be->f2 = htobe16(u.Data2);
    out_be->f3 = htobe16(u.Data3);
    memcpy(out_be->f4, u.Data4, 8);
}

static int vhd_read(struct vhd* vhd, void* buf, size_t size)
{
    if (lseek64(vhd->fd, vhd->offset, SEEK_SET) != vhd->offset) {
        fprintf(stderr, "Error: couldn't seek '%s': %s\n", vhd->name, strerror(errno));
        return -1;
    }
    if (read(vhd->fd, buf, (unsigned)size) != (int)size) {
        fprintf(stderr, "Error: couldn't read from '%s': %s\n", vhd->name, strerror(errno));
        return -1;
    }
    vhd->offset += (off64_t)size; return 0;
}

static int vhd_write(struct vhd* vhd, void* buf, size_t size)
{
    if (lseek64(vhd->fd, vhd->offset, SEEK_SET) != vhd->offset) {
        fprintf(stderr, "Error: couldn't seek '%s': %s\n", vhd->name, strerror(errno));
        return -1;
    }
    if (write(vhd->fd, buf, (unsigned)size) != (int)size) {
        fprintf(stderr, "Error: couldn't write to '%s': %s\n", vhd->name, strerror(errno));
        return -1;
    }
    vhd->offset += (off64_t)size; return 0;
}

static int op_raw_read(struct vhd* vhd, void* buf, off64_t offset, size_t size)
{
    if (offset > vhd->size || (off64_t)(offset + (off64_t)size) > vhd->size) {
        fprintf(stderr, "Error: out-of-bound read from '%s'\n", vhd->name); return -1;
    }
    vhd->offset = offset; return vhd_read(vhd, buf, size);
}

static int op_raw_write(struct vhd* vhd, void* buf, off64_t offset, size_t size)
{
    if (offset > vhd->size || (off64_t)(offset + (off64_t)size) > vhd->size) {
        fprintf(stderr, "Error: out-of-bound write to '%s'\n", vhd->name); return -1;
    }
    vhd->offset = offset; return vhd_write(vhd, buf, size);
}

static int vhd_verify(struct vhd* vhd)
{
    if (vhd->footer.cookie != COOKIE("conectix")) return -1;
    uint32_t type = be32toh(vhd->footer.disk_type);
    if (type != FOOTER_TYPE_FIXED) return -1; /* only fixed verified here */
    vhd->read = op_raw_read; vhd->write = op_raw_write;
    vhd->size = vhd->file_size - (off64_t)sizeof(vhd->footer);
    return 0;
}

static int vhd_open(struct vhd* vhd, char* name, unsigned flags)
{
    memset(vhd, 0, sizeof(*vhd)); vhd->flags = flags; vhd->name = name; vhd->fd = -1;
    if (flags & OPEN_CREAT) {
        vhd->fd = open(vhd->name, O_CREAT | O_EXCL | O_RDWR, _S_IREAD | _S_IWRITE);
    }
    else {
        vhd->fd = open(vhd->name, (flags & OPEN_RW) ? O_RDWR : O_RDONLY, 0);
    }
    if (vhd->fd == -1) {
        fprintf(stderr, "Error: couldn't open '%s': %s\n", vhd->name, strerror(errno)); return -1;
    }
    if (flags & OPEN_CREAT) return 0;

    struct _stat64 st; if (fstat(vhd->fd, &st) == -1) {
        fprintf(stderr, "Error: couldn't stat '%s': %s\n", vhd->name, strerror(errno)); return -1;
    }
    vhd->file_size = (off64_t)st.st_size;
    vhd->offset = vhd->file_size - (off64_t)sizeof(vhd->footer);
    if (vhd_read(vhd, &vhd->footer, sizeof(vhd->footer)) == -1) return -1;

    if (vhd_verify(vhd) == -1) {
        if (flags & OPEN_RAW_OK) {
            fprintf(stderr, "Warning: '%s' treated as raw image\n", vhd->name);
            vhd->read = op_raw_read; vhd->write = op_raw_write; vhd->size = vhd->file_size; return 0;
        }
        return -1;
    }
    return 0;
}

static int vhd_close(struct vhd* vhd, int status)
{
    if (vhd->fd != -1) {
        if (!status) {
            if (fsync(vhd->fd)) { perror("couldn't flush VHD data"); return -1; }
            if (close(vhd->fd)) { perror("couldn't close VHD file"); return -1; }
        }
        else {
            if (vhd->flags & OPEN_CREAT) {
                if (unlink(vhd->name)) { perror("couldn't clean up VHD file"); return -1; }
            }
        }
    }
    return 0;
}

static uint32_t vhd_checksum(uint8_t* data, size_t size)
{
    uint32_t csum = 0; while (size--) csum += *data++; return ~csum;
}

static unsigned min_nz(unsigned a, unsigned b)
{
    return (a < b&& a != 0) ? a : b;
}

static int vhd_chs(struct vhd* vhd)
{
    uint64_t cyl_x_heads; struct vhd_chs chs; uint64_t new_sectors; uint64_t sectors; off64_t original_size = vhd->size;
again:
    sectors = (uint64_t)(vhd->size >> 9);
    if (sectors > 65535ull * 16ull * 255ull) sectors = 65535ull * 16ull * 255ull; /* ~127GiB */
    if (sectors >= 65535ull * 16ull * 63ull) {
        chs.s = 255; chs.h = 16; cyl_x_heads = sectors / chs.s;
    }
    else {
        chs.s = 17; cyl_x_heads = sectors / chs.s; chs.h = (uint8_t)((cyl_x_heads + 1023) >> 10); if (chs.h < 4) chs.h = 4;
        if (cyl_x_heads >= (uint64_t)(chs.h << 10) || chs.h > 16) { chs.s = 31; chs.h = 16; cyl_x_heads = sectors / chs.s; }
        if (cyl_x_heads >= (uint64_t)(chs.h << 10)) { chs.s = 63; chs.h = 16; cyl_x_heads = sectors / chs.s; }
    }
    chs.c = (uint16_t)(cyl_x_heads / chs.h);
    vhd->footer.disk_geometry.c = htobe16(chs.c);
    vhd->footer.disk_geometry.h = chs.h;
    vhd->footer.disk_geometry.s = chs.s;

    if (sectors < 65535ull * 16ull * 255ull) {
        new_sectors = (uint64_t)chs.c * chs.h * chs.s;
        if (new_sectors != sectors) {
            if (original_size == vhd->size) {
                fprintf(stderr,
                    "Warning: C(%u)H(%u)S(%u)-derived total sector count (%llu) does not match actual (%llu)%s.\n",
                    chs.c, chs.h, chs.s,
                    (unsigned long long)new_sectors,
                    (unsigned long long)sectors,
                    (vhd->flags & COMPAT_SIZE) ? " and will be recomputed" : "");
            }
            if (vhd->flags & COMPAT_SIZE) {
                vhd->size = (off64_t)round_up((uint64_t)vhd->size + 1ull,
                    (uint64_t)min_nz(min_nz(chs.c, chs.h), chs.s) << 9);
                goto again;
            }
            fprintf(stderr, "Warning: You may have problems with Hyper-V if converting raw disks to VHD, or if moving VHDs from ATA to SCSI.\n");
        }
    }
    if (original_size != vhd->size) {
        fprintf(stderr, "Warning: increased VHD size from %lld to %lld bytes\n", (long long)original_size, (long long)vhd->size);
    }
    return 0;
}

static int vhd_footer_make(struct vhd* vhd, uint64_t data_offset)
{
    if (((vhd->size >> 9) << 9) != vhd->size) { fprintf(stderr, "Error: size must be in units of 512-byte sectors\n"); return -1; }
    if (vhd_chs(vhd) == -1) { fprintf(stderr, "Error: size is too small\n"); return -1; }
    vhd->footer.cookie = COOKIE("conectix");
    vhd->footer.features = htobe32(FOOTER_FEAT_RSVD);
    vhd->footer.data_offset = htobe64(data_offset);
    vhd->footer.file_format_ver = htobe32(VHD_VERSION_1);
    vhd->footer.time_stamp = htobe32((uint32_t)(time(NULL) + SECONDS_OFFSET));
    vhd->footer.creator_app = COOKIE32("vhdt");
    vhd->footer.creator_ver = htobe32(0x1);
    vhd->footer.creator_os = COOKIE32("Win "); /* was "Lnux"; mark as Windows */
    vhd->footer.original_size = htobe64((uint64_t)vhd->size);
    vhd->footer.current_size = htobe64((uint64_t)vhd->size);
    vhd->footer.disk_type = htobe32(vhd->type);
    uuid_make(&vhd->footer.vhd_id, vhd->uuid_str);
    vhd->footer.checksum = 0; /* checksum computed over zeroed field */
    vhd->footer.checksum = vhd_checksum((uint8_t*)&vhd->footer, sizeof(vhd->footer));
    vhd->footer.checksum = htobe32(vhd->footer.checksum);
    return 0;
}

static int vhd_dyn_make(struct vhd* vhd, uint32_t block_size)
{
    vhd->dyn.cookie = COOKIE("cxsparse");
    vhd->dyn.data_offset = htobe64(DYN_DOFF_DYN);
    vhd->dyn.table_offset = htobe64((uint64_t)(vhd->offset + (off64_t)sizeof(vhd->dyn)));
    vhd->dyn.header_version = htobe32(0x00010000UL);

    if (((block_size >> 9) << 9) != block_size) { fprintf(stderr, "Error: block size must be in units of 512-byte sectors\n"); return -1; }
    vhd->dyn.block_size = htobe32(block_size);

    uint64_t max_tab_entries = (uint64_t)vhd->size / block_size;
    if (!max_tab_entries) { fprintf(stderr, "Error: block size can't be larger than the VHD\n"); return -1; }
    if ((off64_t)(max_tab_entries * (uint64_t)block_size) != vhd->size) {
        fprintf(stderr, "Error: VHD size not multiple of block size\n"); return -1;
    }
    vhd->dyn.max_tab_entries = htobe32((uint32_t)max_tab_entries);
    vhd->dyn.checksum = 0;
    vhd->dyn.checksum = vhd_checksum((uint8_t*)&vhd->dyn, sizeof(vhd->dyn));
    vhd->dyn.checksum = htobe32(vhd->dyn.checksum);
    return 0;
}

static int vhd_create(struct vhd* vhd, off64_t block_size)
{
    int status = 0; if (!block_size) block_size = DYN_BLOCK_SZ;
    if ((status = vhd_footer_make(vhd, (vhd->type == FOOTER_TYPE_FIXED) ? FOOTER_DOFF_FIXED : sizeof(vhd->footer)))) return status;

    printf("Creating %s VHD %s (%llu bytes)\n",
        (vhd->type == FOOTER_TYPE_FIXED ? "fixed" : "dynamic"), vhd->uuid_str,
        (unsigned long long)vhd->size);

    if (vhd->type == FOOTER_TYPE_FIXED) {
        DWORD bytesReturned;
        HANDLE h = (HANDLE)_get_osfhandle(vhd->fd);
        BOOL isSparse = DeviceIoControl(
            h,
            FSCTL_SET_SPARSE,   // 稀疏文件控制码
            NULL, 0,            // 无输入数据
            NULL, 0,            // 无输出数据
            &bytesReturned,
            NULL
        );

        if (!isSparse) {
            printf("设置稀疏文件失败，错误码: %d\n", GetLastError());
            return -1;
        }

        vhd->offset = vhd->size; vhd->read = op_raw_read; vhd->write = op_raw_write;
        return vhd_write(vhd, &vhd->footer, sizeof(vhd->footer));
    }
    else {
        size_t bat_entries; vhd->offset = 0; vhd_batent empty = BAT_ENTRY_EMPTY;
        if ((status = vhd_write(vhd, &vhd->footer, sizeof(vhd->footer)))) return status;
        if ((status = vhd_dyn_make(vhd, (uint32_t)block_size))) return status;
        if ((status = vhd_write(vhd, &vhd->dyn, sizeof(vhd->dyn)))) return status;
        bat_entries = (size_t)((uint64_t)vhd->size / (uint64_t)block_size);
        while (bat_entries--) if ((status = vhd_write(vhd, &empty, sizeof(empty)))) return status;
        vhd->offset = (off64_t)round_up((uint64_t)vhd->offset, 512ull);
        if ((status = vhd_write(vhd, &vhd->footer, sizeof(vhd->footer)))) return status;
    }
    return 0;
}

static int vhd_copy(struct vhd* src, struct vhd* dst)
{
    int status; off64_t pos; uint8_t buf[SEC_SZ];
    printf("Copying contents from '%s' to '%s'\n", src->name, dst->name);
    for (pos = 0; pos < src->size; pos += (off64_t)sizeof(buf)) {
        status = src->read(src, &buf, pos, sizeof(buf)); if (status == -1) return -1;
        status = dst->write(dst, &buf, pos, sizeof(buf)); if (status == -1) return -1;
    }
    return 0;
}

static int vhd_cmd_convert(int optind0, int argc, char** argv, bool size_compat, uint32_t vhd_type, off64_t block_size)
{
    struct vhd src, dest; int status;
    if (optind0 != (argc - 2)) {
        fprintf(stderr, "Usage: %s [-b block_size] [-c] [-t type] convert source-file-name dest-file-name\n", argv[0]);
        return -1;
    }
    if (!vhd_type) vhd_type = block_size ? FOOTER_TYPE_DYN : FOOTER_TYPE_FIXED;
    if (vhd_open(&src, argv[optind0], OPEN_RAW_OK) == -1) return -1;
    if (vhd_open(&dest, argv[optind0 + 1], OPEN_RW | OPEN_CREAT | (size_compat ? COMPAT_SIZE : 0)) == -1) return -1;
    dest.type = vhd_type; dest.size = src.size;
    status = vhd_create(&dest, block_size); if (status == -1) goto done;
    status = vhd_copy(&src, &dest);
done:
    if (vhd_close(&dest, status) == -1) status = -1;
    if (vhd_close(&src, status) == -1) status = -1;
    return status;
}

static int vhd_cmd_create(int optind0, int argc, char** argv, bool size_compat, off64_t vhd_size, uint32_t vhd_type, off64_t block_size)
{
    int status; struct vhd vhd;
    if (optind0 != (argc - 1) || !vhd_size) {
        fprintf(stderr, "Usage: %s -s size [-b block_size] [-c] [-t type] create vhd-file-name\n", argv[0]);
        return -1;
    }
    if (!vhd_type) vhd_type = block_size ? FOOTER_TYPE_DYN : FOOTER_TYPE_FIXED;
    if (vhd_open(&vhd, argv[optind0], OPEN_RW | OPEN_CREAT | (size_compat ? COMPAT_SIZE : 0))) return -1;
    vhd.type = vhd_type; vhd.size = vhd_size;
    status = vhd_create(&vhd, block_size);
    if (vhd_close(&vhd, status)) return -1; return status;
}

/* parse a size like "10G", "64M", "1024K", "512S", or bytes default */
static int parse_size_arg(const char* opt, off64_t* out)
{
    char* end = NULL; unsigned long long val = _strtoui64(opt, &end, 10);
    char type = (end && *end) ? *end : '\0';
    off64_t size = (off64_t)val;
    switch (type) {
    case 't': case 'T': size <<= 10; /* fallthrough */
    case 'g': case 'G': size <<= 10; /* fallthrough */
    case 'm': case 'M': size <<= 10; /* fallthrough */
    case 'k': case 'K': size <<= 10; /* fallthrough */
    case '\0': case 'b': case 'B': break;
    case 's': case 'S': size <<= 9; break; /* sectors */
    default:
        fprintf(stderr, "Error: size modifier '%c' not one of [BKMGTS]\n", type);
        return -1;
    }
    *out = size; return 0;
}

int main(int argc, char** argv)
{
    int status; off64_t vhd_size = 0; uint32_t vhd_type = 0; off64_t block_size = 0; bool do_help = false, do_compat = false;
    while (1) {
        int c; opterr = 0; c = getopt(argc, argv, "cb:s:t:"); if (c == -1) break; else if (c == '?') { do_help = true; break; }
        switch (c) {
        case 'c': do_compat = true; break;
        case 'b': if (parse_size_arg(optarg, &block_size)) return -1; break;
        case 's': if (parse_size_arg(optarg, &vhd_size)) return -1; break;
        case 't': {
            if (_strnicmp("fixed", optarg, 5) == 0) vhd_type = FOOTER_TYPE_FIXED;
            else if (_strnicmp("dynamic", optarg, 7) == 0) vhd_type = FOOTER_TYPE_DYN;
            else { fprintf(stderr, "Error: Disk type not one of 'fixed' or 'dynamic'\n"); return -1; }
            break; }
        }
    }
    if (do_help || optind == argc) {
        fprintf(stderr, "Usage: %s [-s size] [-b block_size] [-c] [-t type] create|convert ...\n", argv[0]);
        return -1;
    }
    if (strcmp(argv[optind], "create") == 0) {
        status = vhd_cmd_create(optind + 1, argc, argv, do_compat, vhd_size, vhd_type, block_size);
    }
    else if (strcmp(argv[optind], "convert") == 0) {
        status = vhd_cmd_convert(optind + 1, argc, argv, do_compat, vhd_type, block_size);
    }
    else {
        fprintf(stderr, "Error: unknown command '%s'\n", argv[optind]);
        return -1;
    }
    if (status == -1) fprintf(stderr, "Error: command '%s' failed\n", argv[optind]);
    return status;
}
