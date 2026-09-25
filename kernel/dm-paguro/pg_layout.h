/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * paguro core: the on-disk structures it reads, as layout descriptions.
 *
 * Every struct here exists only to name offsets and sizes: nothing ever
 * casts a buffer to one (alignment, aliasing, endianness and bounds all stay
 * in the byte accessors of pg_ntfs.c). A field is read with
 *
 *	GET(b, struct ntfs_boot_sector, bytes_per_sector)
 *	GET_AT(r, pos, struct ntfs_attr_nonresident, lowest_vcn)
 *
 * which take offsetof() for the offset and the field's size to pick the
 * little-endian reader. Integer fields are little-endian on disk unless
 * their name ends in _be (ISO 9660's both-endian pairs). Variable-length
 * parts (attribute bodies, runlists, update-sequence arrays, names) remain
 * offset arithmetic from these headers. Every offset and every size is
 * pinned by a static assertion against the format's documentation, so a
 * struct cannot drift.
 *
 * The Rust reference (crates/paguro-core/src/ntfs/layout.rs) has the same
 * structs, fields and constants under the same names.
 */
#ifndef PG_LAYOUT_H
#define PG_LAYOUT_H

#include "pg_range.h"

#ifdef __KERNEL__
#include <linux/stddef.h>
#endif

#if defined(__GNUC__) || defined(__clang__)
#define PG_PACKED __attribute__((packed))
#else
#error "PG_PACKED: packed structs need GCC or Clang"
#endif

/* offset/size of a field, and the static check of both. */
#define PG_OFF(T, f) offsetof(T, f)
#define PG_SIZE(T, f) sizeof(((T *)0)->f)
#define PG_AT(T, f, off) \
	_Static_assert(offsetof(T, f) == (off), #T "." #f " is at " #off)
#define PG_SIZEOF(T, n) _Static_assert(sizeof(T) == (n), #T " is " #n " bytes")

/* ---- NTFS boot sector ($Boot, sector 0) ------------------------------- */
struct ntfs_boot_sector {
	pg_u8 jump[3];
	pg_u8 oem_id[8];
	pg_u16 bytes_per_sector;
	pg_u8 sectors_per_cluster;	/* 1..128, or 2^(256 - v) */
	pg_u16 reserved_sectors;
	pg_u8 zero1[3];
	pg_u16 unused1;
	pg_u8 media_type;
	pg_u16 zero2;
	pg_u16 sectors_per_track;
	pg_u16 number_of_heads;
	pg_u32 hidden_sectors;
	pg_u32 unused2;
	pg_u32 unused3;
	pg_u64 total_sectors;
	pg_u64 mft_lcn;
	pg_u64 mftmirr_lcn;
	pg_u8 clusters_per_mft_record;	/* > 0: clusters; else 2^-v bytes */
	pg_u8 pad1[3];
	pg_u8 clusters_per_index_record;
	pg_u8 pad2[3];
	pg_u64 volume_serial_number;
	pg_u32 checksum;
	pg_u8 bootstrap[426];
	pg_u16 signature;
} PG_PACKED;
PG_AT(struct ntfs_boot_sector, jump, 0x00);
PG_AT(struct ntfs_boot_sector, oem_id, 0x03);
PG_AT(struct ntfs_boot_sector, bytes_per_sector, 0x0b);
PG_AT(struct ntfs_boot_sector, sectors_per_cluster, 0x0d);
PG_AT(struct ntfs_boot_sector, reserved_sectors, 0x0e);
PG_AT(struct ntfs_boot_sector, zero1, 0x10);
PG_AT(struct ntfs_boot_sector, unused1, 0x13);
PG_AT(struct ntfs_boot_sector, media_type, 0x15);
PG_AT(struct ntfs_boot_sector, zero2, 0x16);
PG_AT(struct ntfs_boot_sector, sectors_per_track, 0x18);
PG_AT(struct ntfs_boot_sector, number_of_heads, 0x1a);
PG_AT(struct ntfs_boot_sector, hidden_sectors, 0x1c);
PG_AT(struct ntfs_boot_sector, unused2, 0x20);
PG_AT(struct ntfs_boot_sector, unused3, 0x24);
PG_AT(struct ntfs_boot_sector, total_sectors, 0x28);
PG_AT(struct ntfs_boot_sector, mft_lcn, 0x30);
PG_AT(struct ntfs_boot_sector, mftmirr_lcn, 0x38);
PG_AT(struct ntfs_boot_sector, clusters_per_mft_record, 0x40);
PG_AT(struct ntfs_boot_sector, pad1, 0x41);
PG_AT(struct ntfs_boot_sector, clusters_per_index_record, 0x44);
PG_AT(struct ntfs_boot_sector, pad2, 0x45);
PG_AT(struct ntfs_boot_sector, volume_serial_number, 0x48);
PG_AT(struct ntfs_boot_sector, checksum, 0x50);
PG_AT(struct ntfs_boot_sector, bootstrap, 0x54);
PG_AT(struct ntfs_boot_sector, signature, 0x1fe);
PG_SIZEOF(struct ntfs_boot_sector, 512);

#define BOOT_SIGNATURE 0xaa55		/* NTFS, FAT and MBR boot sectors */
#define NTFS_OEM_ID "NTFS    "
/* Byte-sized counts above this are negative: a power-of-two exponent. */
#define NTFS_BS_NEGATIVE 0x80
#define NTFS_BS_MAX_CLUSTER_SHIFT 20	/* 2^-v sectors per cluster */
#define NTFS_BS_MAX_RECORD_SHIFT 12	/* 2^-v bytes per record */

/* ---- FILE record header (MFT record, NTFS 3.1) ------------------------ */
struct ntfs_file_record {
	pg_u8 magic[4];			/* "FILE" */
	pg_u16 usa_offset;
	pg_u16 usa_count;
	pg_u64 lsn;
	pg_u16 sequence_number;
	pg_u16 link_count;
	pg_u16 attrs_offset;
	pg_u16 flags;			/* NTFS_RECORD_* */
	pg_u32 bytes_in_use;
	pg_u32 bytes_allocated;
	pg_u64 base_mft_record;		/* an MFT reference; 0 in a base */
	pg_u16 next_attr_instance;
	pg_u16 reserved;
	pg_u32 mft_record_number;
} PG_PACKED;
PG_AT(struct ntfs_file_record, magic, 0x00);
PG_AT(struct ntfs_file_record, usa_offset, 0x04);
PG_AT(struct ntfs_file_record, usa_count, 0x06);
PG_AT(struct ntfs_file_record, lsn, 0x08);
PG_AT(struct ntfs_file_record, sequence_number, 0x10);
PG_AT(struct ntfs_file_record, link_count, 0x12);
PG_AT(struct ntfs_file_record, attrs_offset, 0x14);
PG_AT(struct ntfs_file_record, flags, 0x16);
PG_AT(struct ntfs_file_record, bytes_in_use, 0x18);
PG_AT(struct ntfs_file_record, bytes_allocated, 0x1c);
PG_AT(struct ntfs_file_record, base_mft_record, 0x20);
PG_AT(struct ntfs_file_record, next_attr_instance, 0x28);
PG_AT(struct ntfs_file_record, reserved, 0x2a);
PG_AT(struct ntfs_file_record, mft_record_number, 0x2c);
PG_SIZEOF(struct ntfs_file_record, 0x30);

#define NTFS_RECORD_MAGIC "FILE"
/* The update-sequence array follows the 3.1 header; 3.0's (0x2a) refused. */
#define NTFS_USA_OFFSET_31 0x30
#define NTFS_RECORD_IN_USE 0x0001
#define NTFS_RECORD_IS_DIRECTORY 0x0002
/* An MFT reference: 48-bit record number, 16-bit sequence number. */
#define NTFS_MFT_REF_RECORD_MASK 0xffffffffffffull
#define NTFS_MFT_REF_SEQ_SHIFT 48

/* ---- attribute record header, the part both kinds share -------------- */
struct ntfs_attr {
	pg_u32 type;			/* NTFS_AT_* */
	pg_u32 length;
	pg_u8 non_resident;
	pg_u8 name_length;		/* UTF-16 units */
	pg_u16 name_offset;
	pg_u16 flags;			/* NTFS_ATTR_* */
	pg_u16 instance;
} PG_PACKED;
PG_AT(struct ntfs_attr, type, 0x00);
PG_AT(struct ntfs_attr, length, 0x04);
PG_AT(struct ntfs_attr, non_resident, 0x08);
PG_AT(struct ntfs_attr, name_length, 0x09);
PG_AT(struct ntfs_attr, name_offset, 0x0a);
PG_AT(struct ntfs_attr, flags, 0x0c);
PG_AT(struct ntfs_attr, instance, 0x0e);
PG_SIZEOF(struct ntfs_attr, 0x10);

/* ---- resident attribute header ----------------------------------------- */
struct ntfs_attr_resident {
	pg_u8 common[16];		/* struct ntfs_attr */
	pg_u32 value_length;
	pg_u16 value_offset;
	pg_u8 resident_flags;
	pg_u8 reserved;
} PG_PACKED;
PG_AT(struct ntfs_attr_resident, common, 0x00);
PG_AT(struct ntfs_attr_resident, value_length, 0x10);
PG_AT(struct ntfs_attr_resident, value_offset, 0x14);
PG_AT(struct ntfs_attr_resident, resident_flags, 0x16);
PG_AT(struct ntfs_attr_resident, reserved, 0x17);
PG_SIZEOF(struct ntfs_attr_resident, 0x18);

/* ---- non-resident attribute header -------------------------------------- */
struct ntfs_attr_nonresident {
	pg_u8 common[16];		/* struct ntfs_attr */
	pg_u64 lowest_vcn;
	pg_u64 highest_vcn;
	pg_u16 mapping_pairs_offset;
	pg_u8 compression_unit;
	pg_u8 reserved[5];
	pg_u64 allocated_size;
	pg_u64 data_size;
	pg_u64 initialized_size;
} PG_PACKED;
PG_AT(struct ntfs_attr_nonresident, common, 0x00);
PG_AT(struct ntfs_attr_nonresident, lowest_vcn, 0x10);
PG_AT(struct ntfs_attr_nonresident, highest_vcn, 0x18);
PG_AT(struct ntfs_attr_nonresident, mapping_pairs_offset, 0x20);
PG_AT(struct ntfs_attr_nonresident, compression_unit, 0x22);
PG_AT(struct ntfs_attr_nonresident, reserved, 0x23);
PG_AT(struct ntfs_attr_nonresident, allocated_size, 0x28);
PG_AT(struct ntfs_attr_nonresident, data_size, 0x30);
PG_AT(struct ntfs_attr_nonresident, initialized_size, 0x38);
PG_SIZEOF(struct ntfs_attr_nonresident, 0x40);

#define NTFS_AT_ATTRIBUTE_LIST 0x20
#define NTFS_AT_VOLUME_INFORMATION 0x70
#define NTFS_AT_DATA 0x80
#define NTFS_AT_END 0xffffffffu
#define NTFS_ATTR_COMPRESSION_MASK 0x00ff
#define NTFS_ATTR_IS_ENCRYPTED 0x4000
#define NTFS_ATTR_IS_SPARSE 0x8000
/* Mapping pairs: each run's header byte, offset size << 4 | length size. */
#define NTFS_RUN_LENGTH_SIZE_MASK 0x0f
#define NTFS_RUN_OFFSET_SIZE_SHIFT 4
#define NTFS_RUN_MAX_FIELD 8

/* ---- $ATTRIBUTE_LIST entry ------------------------------------------------ */
struct ntfs_attr_list_entry {
	pg_u32 type;
	pg_u16 length;
	pg_u8 name_length;
	pg_u8 name_offset;
	pg_u64 lowest_vcn;
	pg_u64 mft_reference;
	pg_u16 instance;
} PG_PACKED;
PG_AT(struct ntfs_attr_list_entry, type, 0x00);
PG_AT(struct ntfs_attr_list_entry, length, 0x04);
PG_AT(struct ntfs_attr_list_entry, name_length, 0x06);
PG_AT(struct ntfs_attr_list_entry, name_offset, 0x07);
PG_AT(struct ntfs_attr_list_entry, lowest_vcn, 0x08);
PG_AT(struct ntfs_attr_list_entry, mft_reference, 0x10);
PG_AT(struct ntfs_attr_list_entry, instance, 0x18);
PG_SIZEOF(struct ntfs_attr_list_entry, 0x1a);

/* ---- $VOLUME_INFORMATION (the value of attribute 0x70 in $Volume) ---- */
struct ntfs_volume_information {
	pg_u64 reserved;
	pg_u8 major_version;
	pg_u8 minor_version;
	pg_u16 flags;			/* PG_NTFS_VOLUME_DIRTY, ... */
} PG_PACKED;
PG_AT(struct ntfs_volume_information, reserved, 0x00);
PG_AT(struct ntfs_volume_information, major_version, 0x08);
PG_AT(struct ntfs_volume_information, minor_version, 0x09);
PG_AT(struct ntfs_volume_information, flags, 0x0a);
PG_SIZEOF(struct ntfs_volume_information, 12);

#define NTFS_MFT_RECORD_VOLUME 3	/* $Volume */

/* ---- GPT header (UEFI 2.10 §5.3.2) ------------------------------------ */
struct gpt_header {
	pg_u8 signature[8];		/* "EFI PART" */
	pg_u32 revision;
	pg_u32 header_size;
	pg_u32 header_crc32;
	pg_u32 reserved;
	pg_u64 my_lba;
	pg_u64 alternate_lba;
	pg_u64 first_usable_lba;
	pg_u64 last_usable_lba;
	pg_u8 disk_guid[16];
	pg_u64 partition_entry_lba;
	pg_u32 number_of_partition_entries;
	pg_u32 size_of_partition_entry;
	pg_u32 partition_entry_array_crc32;
} PG_PACKED;
PG_AT(struct gpt_header, signature, 0);
PG_AT(struct gpt_header, revision, 8);
PG_AT(struct gpt_header, header_size, 12);
PG_AT(struct gpt_header, header_crc32, 16);
PG_AT(struct gpt_header, reserved, 20);
PG_AT(struct gpt_header, my_lba, 24);
PG_AT(struct gpt_header, alternate_lba, 32);
PG_AT(struct gpt_header, first_usable_lba, 40);
PG_AT(struct gpt_header, last_usable_lba, 48);
PG_AT(struct gpt_header, disk_guid, 56);
PG_AT(struct gpt_header, partition_entry_lba, 72);
PG_AT(struct gpt_header, number_of_partition_entries, 80);
PG_AT(struct gpt_header, size_of_partition_entry, 84);
PG_AT(struct gpt_header, partition_entry_array_crc32, 88);
PG_SIZEOF(struct gpt_header, 92);

/* ---- GPT partition entry (UEFI 2.10 §5.3.3) --------------------------- */
struct gpt_entry {
	pg_u8 partition_type_guid[16];
	pg_u8 unique_partition_guid[16];
	pg_u64 starting_lba;
	pg_u64 ending_lba;
	pg_u64 attributes;
	pg_u8 partition_name[72];
} PG_PACKED;
PG_AT(struct gpt_entry, partition_type_guid, 0);
PG_AT(struct gpt_entry, unique_partition_guid, 16);
PG_AT(struct gpt_entry, starting_lba, 32);
PG_AT(struct gpt_entry, ending_lba, 40);
PG_AT(struct gpt_entry, attributes, 48);
PG_AT(struct gpt_entry, partition_name, 56);
PG_SIZEOF(struct gpt_entry, 128);

#define GPT_SIGNATURE "EFI PART"
#define GPT_MAX_HEADER_SIZE 512		/* what one sector read holds */
#define GPT_MAX_ENTRIES 1024
/* EFI System Partition, C12A7328-F81F-11D2-BA4B-00A0C93EC93B, as stored */
#define GPT_ESP_TYPE { 0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, \
		       0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b }
#define CRC32_POLY 0xedb88320u		/* IEEE 802.3, reflected */

/* ---- FAT12/16 boot sector (BPB + extended BPB) ------------------------- */
struct fat16_boot_sector {
	pg_u8 jump[3];
	pg_u8 oem_name[8];
	pg_u16 bytes_per_sector;
	pg_u8 sectors_per_cluster;
	pg_u16 reserved_sectors;
	pg_u8 number_of_fats;
	pg_u16 root_entries;
	pg_u16 total_sectors_16;	/* 0: see total_sectors_32 */
	pg_u8 media;
	pg_u16 fat_size_16;
	pg_u16 sectors_per_track;
	pg_u16 number_of_heads;
	pg_u32 hidden_sectors;
	pg_u32 total_sectors_32;
	pg_u8 drive_number;
	pg_u8 reserved1;
	pg_u8 boot_signature;
	pg_u32 volume_id;
	pg_u8 volume_label[11];
	pg_u8 fs_type[8];		/* "FAT12   ", "FAT16   " */
	pg_u8 boot_code[448];
	pg_u16 signature;
} PG_PACKED;
PG_AT(struct fat16_boot_sector, jump, 0x00);
PG_AT(struct fat16_boot_sector, oem_name, 0x03);
PG_AT(struct fat16_boot_sector, bytes_per_sector, 0x0b);
PG_AT(struct fat16_boot_sector, sectors_per_cluster, 0x0d);
PG_AT(struct fat16_boot_sector, reserved_sectors, 0x0e);
PG_AT(struct fat16_boot_sector, number_of_fats, 0x10);
PG_AT(struct fat16_boot_sector, root_entries, 0x11);
PG_AT(struct fat16_boot_sector, total_sectors_16, 0x13);
PG_AT(struct fat16_boot_sector, media, 0x15);
PG_AT(struct fat16_boot_sector, fat_size_16, 0x16);
PG_AT(struct fat16_boot_sector, sectors_per_track, 0x18);
PG_AT(struct fat16_boot_sector, number_of_heads, 0x1a);
PG_AT(struct fat16_boot_sector, hidden_sectors, 0x1c);
PG_AT(struct fat16_boot_sector, total_sectors_32, 0x20);
PG_AT(struct fat16_boot_sector, drive_number, 0x24);
PG_AT(struct fat16_boot_sector, reserved1, 0x25);
PG_AT(struct fat16_boot_sector, boot_signature, 0x26);
PG_AT(struct fat16_boot_sector, volume_id, 0x27);
PG_AT(struct fat16_boot_sector, volume_label, 0x2b);
PG_AT(struct fat16_boot_sector, fs_type, 0x36);
PG_AT(struct fat16_boot_sector, boot_code, 0x3e);
PG_AT(struct fat16_boot_sector, signature, 0x1fe);
PG_SIZEOF(struct fat16_boot_sector, 512);

/* ---- FAT32 boot sector (same BPB, FAT32 extended BPB) ------------------ */
struct fat32_boot_sector {
	pg_u8 bpb[36];			/* as struct fat16_boot_sector */
	pg_u32 fat_size_32;
	pg_u16 ext_flags;
	pg_u16 fs_version;
	pg_u32 root_cluster;
	pg_u16 fs_info;
	pg_u16 backup_boot_sector;
	pg_u8 reserved[12];
	pg_u8 drive_number;
	pg_u8 reserved1;
	pg_u8 boot_signature;
	pg_u32 volume_id;
	pg_u8 volume_label[11];
	pg_u8 fs_type[8];		/* "FAT32   " */
	pg_u8 boot_code[420];
	pg_u16 signature;
} PG_PACKED;
PG_AT(struct fat32_boot_sector, bpb, 0x00);
PG_AT(struct fat32_boot_sector, fat_size_32, 0x24);
PG_AT(struct fat32_boot_sector, ext_flags, 0x28);
PG_AT(struct fat32_boot_sector, fs_version, 0x2a);
PG_AT(struct fat32_boot_sector, root_cluster, 0x2c);
PG_AT(struct fat32_boot_sector, fs_info, 0x30);
PG_AT(struct fat32_boot_sector, backup_boot_sector, 0x32);
PG_AT(struct fat32_boot_sector, reserved, 0x34);
PG_AT(struct fat32_boot_sector, drive_number, 0x40);
PG_AT(struct fat32_boot_sector, reserved1, 0x41);
PG_AT(struct fat32_boot_sector, boot_signature, 0x42);
PG_AT(struct fat32_boot_sector, volume_id, 0x43);
PG_AT(struct fat32_boot_sector, volume_label, 0x47);
PG_AT(struct fat32_boot_sector, fs_type, 0x52);
PG_AT(struct fat32_boot_sector, boot_code, 0x5a);
PG_AT(struct fat32_boot_sector, signature, 0x1fe);
PG_SIZEOF(struct fat32_boot_sector, 512);

#define FAT_FS_TYPE "FAT"		/* fat16_boot_sector.fs_type prefix */
#define FAT32_FS_TYPE "FAT32"		/* fat32_boot_sector.fs_type prefix */

/* ---- ext4 superblock (at byte 1024 of the filesystem) ------------------ */
struct ext4_super_block {
	pg_u32 s_inodes_count;
	pg_u32 s_blocks_count_lo;
	pg_u32 s_r_blocks_count_lo;
	pg_u32 s_free_blocks_count_lo;
	pg_u32 s_free_inodes_count;
	pg_u32 s_first_data_block;
	pg_u32 s_log_block_size;
	pg_u32 s_log_cluster_size;
	pg_u32 s_blocks_per_group;
	pg_u32 s_clusters_per_group;
	pg_u32 s_inodes_per_group;
	pg_u32 s_mtime;
	pg_u32 s_wtime;
	pg_u16 s_mnt_count;
	pg_u16 s_max_mnt_count;
	pg_u16 s_magic;
	pg_u16 s_state;
	pg_u16 s_errors;
	pg_u16 s_minor_rev_level;
	pg_u32 s_lastcheck;
	pg_u32 s_checkinterval;
	pg_u32 s_creator_os;
	pg_u32 s_rev_level;
	pg_u16 s_def_resuid;
	pg_u16 s_def_resgid;
	pg_u32 s_first_ino;
	pg_u16 s_inode_size;
	pg_u16 s_block_group_nr;
	pg_u32 s_feature_compat;
	pg_u32 s_feature_incompat;
	pg_u32 s_feature_ro_compat;
	pg_u8 s_uuid[16];
	pg_u8 s_volume_name[16];
	pg_u8 s_last_mounted[64];
	pg_u32 s_algorithm_usage_bitmap;
	pg_u8 s_prealloc_blocks;
	pg_u8 s_prealloc_dir_blocks;
	pg_u16 s_reserved_gdt_blocks;
	pg_u8 s_journal_uuid[16];
	pg_u32 s_journal_inum;
	pg_u32 s_journal_dev;
	pg_u32 s_last_orphan;
	pg_u32 s_hash_seed[4];
	pg_u8 s_def_hash_version;
	pg_u8 s_jnl_backup_type;
	pg_u16 s_desc_size;
	pg_u32 s_default_mount_opts;
	pg_u32 s_first_meta_bg;
	pg_u32 s_mkfs_time;
	pg_u32 s_jnl_blocks[17];
	pg_u32 s_blocks_count_hi;
	pg_u32 s_r_blocks_count_hi;
	pg_u32 s_free_blocks_count_hi;
	pg_u16 s_min_extra_isize;
	pg_u16 s_want_extra_isize;
	pg_u32 s_flags;
	pg_u16 s_raid_stride;
	pg_u16 s_mmp_update_interval;
	pg_u64 s_mmp_block;
	pg_u32 s_raid_stripe_width;
	pg_u8 s_log_groups_per_flex;
	pg_u8 s_checksum_type;
	pg_u8 s_encryption_level;
	pg_u8 s_reserved_pad;
	pg_u64 s_kbytes_written;
	pg_u32 s_snapshot_inum;
	pg_u32 s_snapshot_id;
	pg_u64 s_snapshot_r_blocks_count;
	pg_u32 s_snapshot_list;
	pg_u32 s_error_count;
	pg_u32 s_first_error_time;
	pg_u32 s_first_error_ino;
	pg_u64 s_first_error_block;
	pg_u8 s_first_error_func[32];
	pg_u32 s_first_error_line;
	pg_u32 s_last_error_time;
	pg_u32 s_last_error_ino;
	pg_u32 s_last_error_line;
	pg_u64 s_last_error_block;
	pg_u8 s_last_error_func[32];
	pg_u8 s_mount_opts[64];
	pg_u32 s_usr_quota_inum;
	pg_u32 s_grp_quota_inum;
	pg_u32 s_overhead_clusters;
	pg_u32 s_backup_bgs[2];
	pg_u8 s_encrypt_algos[4];
	pg_u8 s_encrypt_pw_salt[16];
	pg_u32 s_lpf_ino;
	pg_u32 s_prj_quota_inum;
	pg_u32 s_checksum_seed;
	pg_u8 s_reserved[392];		/* s_wtime_hi ... s_reserved */
	pg_u32 s_checksum;
} PG_PACKED;
PG_AT(struct ext4_super_block, s_inodes_count, 0x00);
PG_AT(struct ext4_super_block, s_blocks_count_lo, 0x04);
PG_AT(struct ext4_super_block, s_r_blocks_count_lo, 0x08);
PG_AT(struct ext4_super_block, s_free_blocks_count_lo, 0x0c);
PG_AT(struct ext4_super_block, s_free_inodes_count, 0x10);
PG_AT(struct ext4_super_block, s_first_data_block, 0x14);
PG_AT(struct ext4_super_block, s_log_block_size, 0x18);
PG_AT(struct ext4_super_block, s_log_cluster_size, 0x1c);
PG_AT(struct ext4_super_block, s_blocks_per_group, 0x20);
PG_AT(struct ext4_super_block, s_clusters_per_group, 0x24);
PG_AT(struct ext4_super_block, s_inodes_per_group, 0x28);
PG_AT(struct ext4_super_block, s_mtime, 0x2c);
PG_AT(struct ext4_super_block, s_wtime, 0x30);
PG_AT(struct ext4_super_block, s_mnt_count, 0x34);
PG_AT(struct ext4_super_block, s_max_mnt_count, 0x36);
PG_AT(struct ext4_super_block, s_magic, 0x38);
PG_AT(struct ext4_super_block, s_state, 0x3a);
PG_AT(struct ext4_super_block, s_errors, 0x3c);
PG_AT(struct ext4_super_block, s_minor_rev_level, 0x3e);
PG_AT(struct ext4_super_block, s_lastcheck, 0x40);
PG_AT(struct ext4_super_block, s_checkinterval, 0x44);
PG_AT(struct ext4_super_block, s_creator_os, 0x48);
PG_AT(struct ext4_super_block, s_rev_level, 0x4c);
PG_AT(struct ext4_super_block, s_def_resuid, 0x50);
PG_AT(struct ext4_super_block, s_def_resgid, 0x52);
PG_AT(struct ext4_super_block, s_first_ino, 0x54);
PG_AT(struct ext4_super_block, s_inode_size, 0x58);
PG_AT(struct ext4_super_block, s_block_group_nr, 0x5a);
PG_AT(struct ext4_super_block, s_feature_compat, 0x5c);
PG_AT(struct ext4_super_block, s_feature_incompat, 0x60);
PG_AT(struct ext4_super_block, s_feature_ro_compat, 0x64);
PG_AT(struct ext4_super_block, s_uuid, 0x68);
PG_AT(struct ext4_super_block, s_volume_name, 0x78);
PG_AT(struct ext4_super_block, s_last_mounted, 0x88);
PG_AT(struct ext4_super_block, s_algorithm_usage_bitmap, 0xc8);
PG_AT(struct ext4_super_block, s_prealloc_blocks, 0xcc);
PG_AT(struct ext4_super_block, s_prealloc_dir_blocks, 0xcd);
PG_AT(struct ext4_super_block, s_reserved_gdt_blocks, 0xce);
PG_AT(struct ext4_super_block, s_journal_uuid, 0xd0);
PG_AT(struct ext4_super_block, s_journal_inum, 0xe0);
PG_AT(struct ext4_super_block, s_journal_dev, 0xe4);
PG_AT(struct ext4_super_block, s_last_orphan, 0xe8);
PG_AT(struct ext4_super_block, s_hash_seed, 0xec);
PG_AT(struct ext4_super_block, s_def_hash_version, 0xfc);
PG_AT(struct ext4_super_block, s_jnl_backup_type, 0xfd);
PG_AT(struct ext4_super_block, s_desc_size, 0xfe);
PG_AT(struct ext4_super_block, s_default_mount_opts, 0x100);
PG_AT(struct ext4_super_block, s_first_meta_bg, 0x104);
PG_AT(struct ext4_super_block, s_mkfs_time, 0x108);
PG_AT(struct ext4_super_block, s_jnl_blocks, 0x10c);
PG_AT(struct ext4_super_block, s_blocks_count_hi, 0x150);
PG_AT(struct ext4_super_block, s_r_blocks_count_hi, 0x154);
PG_AT(struct ext4_super_block, s_free_blocks_count_hi, 0x158);
PG_AT(struct ext4_super_block, s_min_extra_isize, 0x15c);
PG_AT(struct ext4_super_block, s_want_extra_isize, 0x15e);
PG_AT(struct ext4_super_block, s_flags, 0x160);
PG_AT(struct ext4_super_block, s_raid_stride, 0x164);
PG_AT(struct ext4_super_block, s_mmp_update_interval, 0x166);
PG_AT(struct ext4_super_block, s_mmp_block, 0x168);
PG_AT(struct ext4_super_block, s_raid_stripe_width, 0x170);
PG_AT(struct ext4_super_block, s_log_groups_per_flex, 0x174);
PG_AT(struct ext4_super_block, s_checksum_type, 0x175);
PG_AT(struct ext4_super_block, s_encryption_level, 0x176);
PG_AT(struct ext4_super_block, s_reserved_pad, 0x177);
PG_AT(struct ext4_super_block, s_kbytes_written, 0x178);
PG_AT(struct ext4_super_block, s_snapshot_inum, 0x180);
PG_AT(struct ext4_super_block, s_snapshot_id, 0x184);
PG_AT(struct ext4_super_block, s_snapshot_r_blocks_count, 0x188);
PG_AT(struct ext4_super_block, s_snapshot_list, 0x190);
PG_AT(struct ext4_super_block, s_error_count, 0x194);
PG_AT(struct ext4_super_block, s_first_error_time, 0x198);
PG_AT(struct ext4_super_block, s_first_error_ino, 0x19c);
PG_AT(struct ext4_super_block, s_first_error_block, 0x1a0);
PG_AT(struct ext4_super_block, s_first_error_func, 0x1a8);
PG_AT(struct ext4_super_block, s_first_error_line, 0x1c8);
PG_AT(struct ext4_super_block, s_last_error_time, 0x1cc);
PG_AT(struct ext4_super_block, s_last_error_ino, 0x1d0);
PG_AT(struct ext4_super_block, s_last_error_line, 0x1d4);
PG_AT(struct ext4_super_block, s_last_error_block, 0x1d8);
PG_AT(struct ext4_super_block, s_last_error_func, 0x1e0);
PG_AT(struct ext4_super_block, s_mount_opts, 0x200);
PG_AT(struct ext4_super_block, s_usr_quota_inum, 0x240);
PG_AT(struct ext4_super_block, s_grp_quota_inum, 0x244);
PG_AT(struct ext4_super_block, s_overhead_clusters, 0x248);
PG_AT(struct ext4_super_block, s_backup_bgs, 0x24c);
PG_AT(struct ext4_super_block, s_encrypt_algos, 0x254);
PG_AT(struct ext4_super_block, s_encrypt_pw_salt, 0x258);
PG_AT(struct ext4_super_block, s_lpf_ino, 0x268);
PG_AT(struct ext4_super_block, s_prj_quota_inum, 0x26c);
PG_AT(struct ext4_super_block, s_checksum_seed, 0x270);
PG_AT(struct ext4_super_block, s_reserved, 0x274);
PG_AT(struct ext4_super_block, s_checksum, 0x3fc);
PG_SIZEOF(struct ext4_super_block, 1024);

/* ---- ext4 block group descriptor (64-byte form) ------------------------ */
struct ext4_group_desc {
	pg_u32 bg_block_bitmap_lo;
	pg_u32 bg_inode_bitmap_lo;
	pg_u32 bg_inode_table_lo;
	pg_u16 bg_free_blocks_count_lo;
	pg_u16 bg_free_inodes_count_lo;
	pg_u16 bg_used_dirs_count_lo;
	pg_u16 bg_flags;
	pg_u32 bg_exclude_bitmap_lo;
	pg_u16 bg_block_bitmap_csum_lo;
	pg_u16 bg_inode_bitmap_csum_lo;
	pg_u16 bg_itable_unused_lo;
	pg_u16 bg_checksum;
	pg_u32 bg_block_bitmap_hi;	/* from here on: 64bit only */
	pg_u32 bg_inode_bitmap_hi;
	pg_u32 bg_inode_table_hi;
	pg_u16 bg_free_blocks_count_hi;
	pg_u16 bg_free_inodes_count_hi;
	pg_u16 bg_used_dirs_count_hi;
	pg_u16 bg_itable_unused_hi;
	pg_u32 bg_exclude_bitmap_hi;
	pg_u16 bg_block_bitmap_csum_hi;
	pg_u16 bg_inode_bitmap_csum_hi;
	pg_u32 bg_reserved;
} PG_PACKED;
PG_AT(struct ext4_group_desc, bg_block_bitmap_lo, 0x00);
PG_AT(struct ext4_group_desc, bg_inode_bitmap_lo, 0x04);
PG_AT(struct ext4_group_desc, bg_inode_table_lo, 0x08);
PG_AT(struct ext4_group_desc, bg_free_blocks_count_lo, 0x0c);
PG_AT(struct ext4_group_desc, bg_free_inodes_count_lo, 0x0e);
PG_AT(struct ext4_group_desc, bg_used_dirs_count_lo, 0x10);
PG_AT(struct ext4_group_desc, bg_flags, 0x12);
PG_AT(struct ext4_group_desc, bg_exclude_bitmap_lo, 0x14);
PG_AT(struct ext4_group_desc, bg_block_bitmap_csum_lo, 0x18);
PG_AT(struct ext4_group_desc, bg_inode_bitmap_csum_lo, 0x1a);
PG_AT(struct ext4_group_desc, bg_itable_unused_lo, 0x1c);
PG_AT(struct ext4_group_desc, bg_checksum, 0x1e);
PG_AT(struct ext4_group_desc, bg_block_bitmap_hi, 0x20);
PG_AT(struct ext4_group_desc, bg_inode_bitmap_hi, 0x24);
PG_AT(struct ext4_group_desc, bg_inode_table_hi, 0x28);
PG_AT(struct ext4_group_desc, bg_free_blocks_count_hi, 0x2c);
PG_AT(struct ext4_group_desc, bg_free_inodes_count_hi, 0x2e);
PG_AT(struct ext4_group_desc, bg_used_dirs_count_hi, 0x30);
PG_AT(struct ext4_group_desc, bg_itable_unused_hi, 0x32);
PG_AT(struct ext4_group_desc, bg_exclude_bitmap_hi, 0x34);
PG_AT(struct ext4_group_desc, bg_block_bitmap_csum_hi, 0x38);
PG_AT(struct ext4_group_desc, bg_inode_bitmap_csum_hi, 0x3a);
PG_AT(struct ext4_group_desc, bg_reserved, 0x3c);
PG_SIZEOF(struct ext4_group_desc, 64);

/* ---- ext4 inode (the first 128 bytes, "good old" size) ----------------- */
struct ext4_inode {
	pg_u16 i_mode;
	pg_u16 i_uid;
	pg_u32 i_size_lo;
	pg_u32 i_atime;
	pg_u32 i_ctime;
	pg_u32 i_mtime;
	pg_u32 i_dtime;
	pg_u16 i_gid;
	pg_u16 i_links_count;
	pg_u32 i_blocks_lo;
	pg_u32 i_flags;
	pg_u32 i_osd1;
	pg_u8 i_block[60];		/* starts with an ext4_extent_header */
	pg_u32 i_generation;
	pg_u32 i_file_acl_lo;
	pg_u32 i_size_high;
	pg_u32 i_obso_faddr;
	pg_u8 i_osd2[12];
} PG_PACKED;
PG_AT(struct ext4_inode, i_mode, 0x00);
PG_AT(struct ext4_inode, i_uid, 0x02);
PG_AT(struct ext4_inode, i_size_lo, 0x04);
PG_AT(struct ext4_inode, i_atime, 0x08);
PG_AT(struct ext4_inode, i_ctime, 0x0c);
PG_AT(struct ext4_inode, i_mtime, 0x10);
PG_AT(struct ext4_inode, i_dtime, 0x14);
PG_AT(struct ext4_inode, i_gid, 0x18);
PG_AT(struct ext4_inode, i_links_count, 0x1a);
PG_AT(struct ext4_inode, i_blocks_lo, 0x1c);
PG_AT(struct ext4_inode, i_flags, 0x20);
PG_AT(struct ext4_inode, i_osd1, 0x24);
PG_AT(struct ext4_inode, i_block, 0x28);
PG_AT(struct ext4_inode, i_generation, 0x64);
PG_AT(struct ext4_inode, i_file_acl_lo, 0x68);
PG_AT(struct ext4_inode, i_size_high, 0x6c);
PG_AT(struct ext4_inode, i_obso_faddr, 0x70);
PG_AT(struct ext4_inode, i_osd2, 0x74);
PG_SIZEOF(struct ext4_inode, 128);

/* ---- ext4 extent tree header (at the start of i_block) ----------------- */
struct ext4_extent_header {
	pg_u16 eh_magic;
	pg_u16 eh_entries;
	pg_u16 eh_max;
	pg_u16 eh_depth;
	pg_u32 eh_generation;
} PG_PACKED;
PG_AT(struct ext4_extent_header, eh_magic, 0);
PG_AT(struct ext4_extent_header, eh_entries, 2);
PG_AT(struct ext4_extent_header, eh_max, 4);
PG_AT(struct ext4_extent_header, eh_depth, 6);
PG_AT(struct ext4_extent_header, eh_generation, 8);
PG_SIZEOF(struct ext4_extent_header, 12);

#define EXT4_SUPERBLOCK_OFFSET 1024	/* bytes into the filesystem */
#define EXT4_SUPER_MAGIC 0xef53
#define EXT4_EXT_MAGIC 0xf30a
#define EXT4_DYNAMIC_REV 1		/* feature words and s_inode_size */
#define EXT4_GOOD_OLD_INODE_SIZE 128
#define EXT4_MAX_LOG_BLOCK_SIZE 6	/* 1024 << 6 = 64 KiB */
#define EXT4_MIN_DESC_SIZE 32
#define EXT4_MIN_DESC_SIZE_64BIT 64
#define EXT4_MAX_DESC_SIZE 1024
#define EXT4_FEATURE_COMPAT_SPARSE_SUPER2 0x0200
#define EXT4_FEATURE_INCOMPAT_64BIT 0x0080
#define EXT4_ROOT_INO 2
#define EXT4_S_IFMT 0xf000
#define EXT4_S_IFDIR 0x4000

/* ---- ISO 9660 directory record ---------------------------------------- */
struct iso_directory_record {
	pg_u8 length;
	pg_u8 ext_attr_length;
	pg_u32 extent_le;
	pg_u32 extent_be;
	pg_u32 data_length_le;
	pg_u32 data_length_be;
	pg_u8 recording_date[7];
	pg_u8 file_flags;		/* ISO_FLAG_* */
	pg_u8 file_unit_size;
	pg_u8 interleave_gap;
	pg_u16 volume_sequence_number_le;
	pg_u16 volume_sequence_number_be;
	pg_u8 name_length;
	pg_u8 name[1];			/* the root's: one byte, 0 ("." ) */
} PG_PACKED;
PG_AT(struct iso_directory_record, length, 0);
PG_AT(struct iso_directory_record, ext_attr_length, 1);
PG_AT(struct iso_directory_record, extent_le, 2);
PG_AT(struct iso_directory_record, extent_be, 6);
PG_AT(struct iso_directory_record, data_length_le, 10);
PG_AT(struct iso_directory_record, data_length_be, 14);
PG_AT(struct iso_directory_record, recording_date, 18);
PG_AT(struct iso_directory_record, file_flags, 25);
PG_AT(struct iso_directory_record, file_unit_size, 26);
PG_AT(struct iso_directory_record, interleave_gap, 27);
PG_AT(struct iso_directory_record, volume_sequence_number_le, 28);
PG_AT(struct iso_directory_record, volume_sequence_number_be, 30);
PG_AT(struct iso_directory_record, name_length, 32);
PG_AT(struct iso_directory_record, name, 33);
PG_SIZEOF(struct iso_directory_record, 34);

/* ---- ISO 9660 primary volume descriptor (ECMA-119 8.4) ----------------- */
struct iso_primary_volume_descriptor {
	pg_u8 type;			/* ISO_VD_PRIMARY */
	pg_u8 id[5];			/* "CD001" */
	pg_u8 version;
	pg_u8 unused1;
	pg_u8 system_id[32];
	pg_u8 volume_id[32];
	pg_u8 unused2[8];
	pg_u32 volume_space_size_le;
	pg_u32 volume_space_size_be;
	pg_u8 unused3[32];
	pg_u16 volume_set_size_le;
	pg_u16 volume_set_size_be;
	pg_u16 volume_sequence_number_le;
	pg_u16 volume_sequence_number_be;
	pg_u16 logical_block_size_le;
	pg_u16 logical_block_size_be;
	pg_u32 path_table_size_le;
	pg_u32 path_table_size_be;
	pg_u32 type_l_path_table;
	pg_u32 opt_type_l_path_table;
	pg_u32 type_m_path_table;
	pg_u32 opt_type_m_path_table;
	pg_u8 root_directory_record[34];	/* struct iso_directory_record */
	pg_u8 volume_set_id[128];
	pg_u8 publisher_id[128];
	pg_u8 preparer_id[128];
	pg_u8 application_id[128];
	pg_u8 copyright_file_id[37];
	pg_u8 abstract_file_id[37];
	pg_u8 bibliographic_file_id[37];
	pg_u8 creation_date[17];
	pg_u8 modification_date[17];
	pg_u8 expiration_date[17];
	pg_u8 effective_date[17];
	pg_u8 file_structure_version;
	pg_u8 unused4;
	pg_u8 application_use[512];
	pg_u8 reserved[653];
} PG_PACKED;
PG_AT(struct iso_primary_volume_descriptor, type, 0);
PG_AT(struct iso_primary_volume_descriptor, id, 1);
PG_AT(struct iso_primary_volume_descriptor, version, 6);
PG_AT(struct iso_primary_volume_descriptor, unused1, 7);
PG_AT(struct iso_primary_volume_descriptor, system_id, 8);
PG_AT(struct iso_primary_volume_descriptor, volume_id, 40);
PG_AT(struct iso_primary_volume_descriptor, unused2, 72);
PG_AT(struct iso_primary_volume_descriptor, volume_space_size_le, 80);
PG_AT(struct iso_primary_volume_descriptor, volume_space_size_be, 84);
PG_AT(struct iso_primary_volume_descriptor, unused3, 88);
PG_AT(struct iso_primary_volume_descriptor, volume_set_size_le, 120);
PG_AT(struct iso_primary_volume_descriptor, volume_set_size_be, 122);
PG_AT(struct iso_primary_volume_descriptor, volume_sequence_number_le, 124);
PG_AT(struct iso_primary_volume_descriptor, volume_sequence_number_be, 126);
PG_AT(struct iso_primary_volume_descriptor, logical_block_size_le, 128);
PG_AT(struct iso_primary_volume_descriptor, logical_block_size_be, 130);
PG_AT(struct iso_primary_volume_descriptor, path_table_size_le, 132);
PG_AT(struct iso_primary_volume_descriptor, path_table_size_be, 136);
PG_AT(struct iso_primary_volume_descriptor, type_l_path_table, 140);
PG_AT(struct iso_primary_volume_descriptor, opt_type_l_path_table, 144);
PG_AT(struct iso_primary_volume_descriptor, type_m_path_table, 148);
PG_AT(struct iso_primary_volume_descriptor, opt_type_m_path_table, 152);
PG_AT(struct iso_primary_volume_descriptor, root_directory_record, 156);
PG_AT(struct iso_primary_volume_descriptor, volume_set_id, 190);
PG_AT(struct iso_primary_volume_descriptor, publisher_id, 318);
PG_AT(struct iso_primary_volume_descriptor, preparer_id, 446);
PG_AT(struct iso_primary_volume_descriptor, application_id, 574);
PG_AT(struct iso_primary_volume_descriptor, copyright_file_id, 702);
PG_AT(struct iso_primary_volume_descriptor, abstract_file_id, 739);
PG_AT(struct iso_primary_volume_descriptor, bibliographic_file_id, 776);
PG_AT(struct iso_primary_volume_descriptor, creation_date, 813);
PG_AT(struct iso_primary_volume_descriptor, modification_date, 830);
PG_AT(struct iso_primary_volume_descriptor, expiration_date, 847);
PG_AT(struct iso_primary_volume_descriptor, effective_date, 864);
PG_AT(struct iso_primary_volume_descriptor, file_structure_version, 881);
PG_AT(struct iso_primary_volume_descriptor, unused4, 882);
PG_AT(struct iso_primary_volume_descriptor, application_use, 883);
PG_AT(struct iso_primary_volume_descriptor, reserved, 1395);
PG_SIZEOF(struct iso_primary_volume_descriptor, 2048);

#define ISO_PVD_OFFSET 32768		/* system area: 16 sectors of 2048 */
#define ISO_VD_PRIMARY 1
#define ISO_STANDARD_ID "CD001"
#define ISO_VD_VERSION 1
#define ISO_FLAG_DIRECTORY 0x02

#endif
