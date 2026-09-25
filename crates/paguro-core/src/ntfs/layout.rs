//! The on-disk structures the core reads, as layout descriptions: the Rust
//! twin of `kernel/dm-paguro/pg_layout.h`, with the same struct, field and
//! constant names so the two can be compared side by side.
//!
//! No value of these types is ever built or read: the structs only name
//! offsets (`offset_of!`) and widths (the field's type), which [`get!`] and
//! [`get_at!`] feed to the checked little-endian readers. Integer fields are
//! little-endian unless their name ends in `_be`. Variable-length parts
//! (attribute bodies, runlists, update-sequence arrays, names) stay offset
//! arithmetic from these headers. Every field's offset and every struct's
//! size is asserted at compile time against the format's documentation.
#![allow(non_camel_case_types, dead_code)]

/// Width of a field, from a function that names it; the struct is never
/// built, the function never called.
pub(crate) fn field_size<T, F>(_: fn(T) -> F) -> usize {
    core::mem::size_of::<F>()
}

/// A field of a layout struct in `b`: `get!(b, ntfs_file_record, flags)`.
macro_rules! get {
    ($b:expr, $t:ident, $f:ident) => {
        get_at!($b, 0usize, $t, $f)
    };
}

/// A field of a layout struct at offset `at` of `b`.
macro_rules! get_at {
    ($b:expr, $at:expr, $t:ident, $f:ident) => {
        $crate::ntfs::get(
            $b,
            $at + core::mem::offset_of!($crate::ntfs::layout::$t, $f),
            $crate::ntfs::layout::field_size(|x: $crate::ntfs::layout::$t| x.$f),
        )
    };
}

/// A field's offset: `off!(gpt_header, disk_guid)`.
macro_rules! off {
    ($t:ident, $f:ident) => {
        core::mem::offset_of!($crate::ntfs::layout::$t, $f)
    };
}

/// A field's width.
macro_rules! width {
    ($t:ident, $f:ident) => {
        $crate::ntfs::layout::field_size(|x: $crate::ntfs::layout::$t| x.$f)
    };
}

/// Compile-time checks: every field at its documented offset, the struct
/// its documented size.
macro_rules! layout {
    ($t:ident, $size:expr; $($f:ident = $o:expr),* $(,)?) => {
        const _: () = {
            $(assert!(core::mem::offset_of!($t, $f) == $o);)*
            assert!(core::mem::size_of::<$t>() == $size);
        };
    };
}

/// NTFS boot sector ($Boot, sector 0)
#[repr(C, packed)]
pub struct ntfs_boot_sector {
    pub jump: [u8; 3],
    pub oem_id: [u8; 8],
    pub bytes_per_sector: u16,
    /// 1..128, or 2^(256 - v)
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub zero1: [u8; 3],
    pub unused1: u16,
    pub media_type: u8,
    pub zero2: u16,
    pub sectors_per_track: u16,
    pub number_of_heads: u16,
    pub hidden_sectors: u32,
    pub unused2: u32,
    pub unused3: u32,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mftmirr_lcn: u64,
    /// > 0: clusters; else 2^-v bytes
    pub clusters_per_mft_record: u8,
    pub pad1: [u8; 3],
    pub clusters_per_index_record: u8,
    pub pad2: [u8; 3],
    pub volume_serial_number: u64,
    pub checksum: u32,
    pub bootstrap: [u8; 426],
    pub signature: u16,
}
layout!(ntfs_boot_sector, 512; jump = 0x00, oem_id = 0x03, bytes_per_sector = 0x0b, sectors_per_cluster = 0x0d, reserved_sectors = 0x0e, zero1 = 0x10, unused1 = 0x13, media_type = 0x15, zero2 = 0x16, sectors_per_track = 0x18, number_of_heads = 0x1a, hidden_sectors = 0x1c, unused2 = 0x20, unused3 = 0x24, total_sectors = 0x28, mft_lcn = 0x30, mftmirr_lcn = 0x38, clusters_per_mft_record = 0x40, pad1 = 0x41, clusters_per_index_record = 0x44, pad2 = 0x45, volume_serial_number = 0x48, checksum = 0x50, bootstrap = 0x54, signature = 0x1fe);

/// FILE record header (MFT record, NTFS 3.1)
#[repr(C, packed)]
pub struct ntfs_file_record {
    /// "FILE"
    pub magic: [u8; 4],
    pub usa_offset: u16,
    pub usa_count: u16,
    pub lsn: u64,
    pub sequence_number: u16,
    pub link_count: u16,
    pub attrs_offset: u16,
    /// NTFS_RECORD_*
    pub flags: u16,
    pub bytes_in_use: u32,
    pub bytes_allocated: u32,
    /// an MFT reference; 0 in a base
    pub base_mft_record: u64,
    pub next_attr_instance: u16,
    pub reserved: u16,
    pub mft_record_number: u32,
}
layout!(ntfs_file_record, 0x30; magic = 0x00, usa_offset = 0x04, usa_count = 0x06, lsn = 0x08, sequence_number = 0x10, link_count = 0x12, attrs_offset = 0x14, flags = 0x16, bytes_in_use = 0x18, bytes_allocated = 0x1c, base_mft_record = 0x20, next_attr_instance = 0x28, reserved = 0x2a, mft_record_number = 0x2c);

/// attribute record header, the part both kinds share
#[repr(C, packed)]
pub struct ntfs_attr {
    /// NTFS_AT_*
    pub r#type: u32,
    pub length: u32,
    pub non_resident: u8,
    /// UTF-16 units
    pub name_length: u8,
    pub name_offset: u16,
    /// NTFS_ATTR_*
    pub flags: u16,
    pub instance: u16,
}
layout!(ntfs_attr, 0x10; r#type = 0x00, length = 0x04, non_resident = 0x08, name_length = 0x09, name_offset = 0x0a, flags = 0x0c, instance = 0x0e);

/// resident attribute header
#[repr(C, packed)]
pub struct ntfs_attr_resident {
    /// struct ntfs_attr
    pub common: [u8; 16],
    pub value_length: u32,
    pub value_offset: u16,
    pub resident_flags: u8,
    pub reserved: u8,
}
layout!(ntfs_attr_resident, 0x18; common = 0x00, value_length = 0x10, value_offset = 0x14, resident_flags = 0x16, reserved = 0x17);

/// non-resident attribute header
#[repr(C, packed)]
pub struct ntfs_attr_nonresident {
    /// struct ntfs_attr
    pub common: [u8; 16],
    pub lowest_vcn: u64,
    pub highest_vcn: u64,
    pub mapping_pairs_offset: u16,
    pub compression_unit: u8,
    pub reserved: [u8; 5],
    pub allocated_size: u64,
    pub data_size: u64,
    pub initialized_size: u64,
}
layout!(ntfs_attr_nonresident, 0x40; common = 0x00, lowest_vcn = 0x10, highest_vcn = 0x18, mapping_pairs_offset = 0x20, compression_unit = 0x22, reserved = 0x23, allocated_size = 0x28, data_size = 0x30, initialized_size = 0x38);

/// $ATTRIBUTE_LIST entry
#[repr(C, packed)]
pub struct ntfs_attr_list_entry {
    pub r#type: u32,
    pub length: u16,
    pub name_length: u8,
    pub name_offset: u8,
    pub lowest_vcn: u64,
    pub mft_reference: u64,
    pub instance: u16,
}
layout!(ntfs_attr_list_entry, 0x1a; r#type = 0x00, length = 0x04, name_length = 0x06, name_offset = 0x07, lowest_vcn = 0x08, mft_reference = 0x10, instance = 0x18);

/// $VOLUME_INFORMATION (the value of attribute 0x70 in $Volume)
#[repr(C, packed)]
pub struct ntfs_volume_information {
    pub reserved: u64,
    pub major_version: u8,
    pub minor_version: u8,
    /// PG_NTFS_VOLUME_DIRTY, ...
    pub flags: u16,
}
layout!(ntfs_volume_information, 12; reserved = 0x00, major_version = 0x08, minor_version = 0x09, flags = 0x0a);

/// GPT header (UEFI 2.10 §5.3.2)
#[repr(C, packed)]
pub struct gpt_header {
    /// "EFI PART"
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub reserved: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub number_of_partition_entries: u32,
    pub size_of_partition_entry: u32,
    pub partition_entry_array_crc32: u32,
}
layout!(gpt_header, 92; signature = 0, revision = 8, header_size = 12, header_crc32 = 16, reserved = 20, my_lba = 24, alternate_lba = 32, first_usable_lba = 40, last_usable_lba = 48, disk_guid = 56, partition_entry_lba = 72, number_of_partition_entries = 80, size_of_partition_entry = 84, partition_entry_array_crc32 = 88);

/// GPT partition entry (UEFI 2.10 §5.3.3)
#[repr(C, packed)]
pub struct gpt_entry {
    pub partition_type_guid: [u8; 16],
    pub unique_partition_guid: [u8; 16],
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub partition_name: [u8; 72],
}
layout!(gpt_entry, 128; partition_type_guid = 0, unique_partition_guid = 16, starting_lba = 32, ending_lba = 40, attributes = 48, partition_name = 56);

/// FAT12/16 boot sector (BPB + extended BPB)
#[repr(C, packed)]
pub struct fat16_boot_sector {
    pub jump: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub number_of_fats: u8,
    pub root_entries: u16,
    /// 0: see total_sectors_32
    pub total_sectors_16: u16,
    pub media: u8,
    pub fat_size_16: u16,
    pub sectors_per_track: u16,
    pub number_of_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    pub drive_number: u8,
    pub reserved1: u8,
    pub boot_signature: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
    /// "FAT12   ", "FAT16   "
    pub fs_type: [u8; 8],
    pub boot_code: [u8; 448],
    pub signature: u16,
}
layout!(fat16_boot_sector, 512; jump = 0x00, oem_name = 0x03, bytes_per_sector = 0x0b, sectors_per_cluster = 0x0d, reserved_sectors = 0x0e, number_of_fats = 0x10, root_entries = 0x11, total_sectors_16 = 0x13, media = 0x15, fat_size_16 = 0x16, sectors_per_track = 0x18, number_of_heads = 0x1a, hidden_sectors = 0x1c, total_sectors_32 = 0x20, drive_number = 0x24, reserved1 = 0x25, boot_signature = 0x26, volume_id = 0x27, volume_label = 0x2b, fs_type = 0x36, boot_code = 0x3e, signature = 0x1fe);

/// FAT32 boot sector (same BPB, FAT32 extended BPB)
#[repr(C, packed)]
pub struct fat32_boot_sector {
    /// as struct fat16_boot_sector
    pub bpb: [u8; 36],
    pub fat_size_32: u32,
    pub ext_flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fs_info: u16,
    pub backup_boot_sector: u16,
    pub reserved: [u8; 12],
    pub drive_number: u8,
    pub reserved1: u8,
    pub boot_signature: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
    /// "FAT32   "
    pub fs_type: [u8; 8],
    pub boot_code: [u8; 420],
    pub signature: u16,
}
layout!(fat32_boot_sector, 512; bpb = 0x00, fat_size_32 = 0x24, ext_flags = 0x28, fs_version = 0x2a, root_cluster = 0x2c, fs_info = 0x30, backup_boot_sector = 0x32, reserved = 0x34, drive_number = 0x40, reserved1 = 0x41, boot_signature = 0x42, volume_id = 0x43, volume_label = 0x47, fs_type = 0x52, boot_code = 0x5a, signature = 0x1fe);

/// ext4 superblock (at byte 1024 of the filesystem)
#[repr(C, packed)]
pub struct ext4_super_block {
    pub s_inodes_count: u32,
    pub s_blocks_count_lo: u32,
    pub s_r_blocks_count_lo: u32,
    pub s_free_blocks_count_lo: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
    pub s_reserved_gdt_blocks: u16,
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u32,
    pub s_jnl_blocks: [u32; 17],
    pub s_blocks_count_hi: u32,
    pub s_r_blocks_count_hi: u32,
    pub s_free_blocks_count_hi: u32,
    pub s_min_extra_isize: u16,
    pub s_want_extra_isize: u16,
    pub s_flags: u32,
    pub s_raid_stride: u16,
    pub s_mmp_update_interval: u16,
    pub s_mmp_block: u64,
    pub s_raid_stripe_width: u32,
    pub s_log_groups_per_flex: u8,
    pub s_checksum_type: u8,
    pub s_encryption_level: u8,
    pub s_reserved_pad: u8,
    pub s_kbytes_written: u64,
    pub s_snapshot_inum: u32,
    pub s_snapshot_id: u32,
    pub s_snapshot_r_blocks_count: u64,
    pub s_snapshot_list: u32,
    pub s_error_count: u32,
    pub s_first_error_time: u32,
    pub s_first_error_ino: u32,
    pub s_first_error_block: u64,
    pub s_first_error_func: [u8; 32],
    pub s_first_error_line: u32,
    pub s_last_error_time: u32,
    pub s_last_error_ino: u32,
    pub s_last_error_line: u32,
    pub s_last_error_block: u64,
    pub s_last_error_func: [u8; 32],
    pub s_mount_opts: [u8; 64],
    pub s_usr_quota_inum: u32,
    pub s_grp_quota_inum: u32,
    pub s_overhead_clusters: u32,
    pub s_backup_bgs: [u32; 2],
    pub s_encrypt_algos: [u8; 4],
    pub s_encrypt_pw_salt: [u8; 16],
    pub s_lpf_ino: u32,
    pub s_prj_quota_inum: u32,
    pub s_checksum_seed: u32,
    /// s_wtime_hi ... s_reserved
    pub s_reserved: [u8; 392],
    pub s_checksum: u32,
}
layout!(ext4_super_block, 1024; s_inodes_count = 0x00, s_blocks_count_lo = 0x04, s_r_blocks_count_lo = 0x08, s_free_blocks_count_lo = 0x0c, s_free_inodes_count = 0x10, s_first_data_block = 0x14, s_log_block_size = 0x18, s_log_cluster_size = 0x1c, s_blocks_per_group = 0x20, s_clusters_per_group = 0x24, s_inodes_per_group = 0x28, s_mtime = 0x2c, s_wtime = 0x30, s_mnt_count = 0x34, s_max_mnt_count = 0x36, s_magic = 0x38, s_state = 0x3a, s_errors = 0x3c, s_minor_rev_level = 0x3e, s_lastcheck = 0x40, s_checkinterval = 0x44, s_creator_os = 0x48, s_rev_level = 0x4c, s_def_resuid = 0x50, s_def_resgid = 0x52, s_first_ino = 0x54, s_inode_size = 0x58, s_block_group_nr = 0x5a, s_feature_compat = 0x5c, s_feature_incompat = 0x60, s_feature_ro_compat = 0x64, s_uuid = 0x68, s_volume_name = 0x78, s_last_mounted = 0x88, s_algorithm_usage_bitmap = 0xc8, s_prealloc_blocks = 0xcc, s_prealloc_dir_blocks = 0xcd, s_reserved_gdt_blocks = 0xce, s_journal_uuid = 0xd0, s_journal_inum = 0xe0, s_journal_dev = 0xe4, s_last_orphan = 0xe8, s_hash_seed = 0xec, s_def_hash_version = 0xfc, s_jnl_backup_type = 0xfd, s_desc_size = 0xfe, s_default_mount_opts = 0x100, s_first_meta_bg = 0x104, s_mkfs_time = 0x108, s_jnl_blocks = 0x10c, s_blocks_count_hi = 0x150, s_r_blocks_count_hi = 0x154, s_free_blocks_count_hi = 0x158, s_min_extra_isize = 0x15c, s_want_extra_isize = 0x15e, s_flags = 0x160, s_raid_stride = 0x164, s_mmp_update_interval = 0x166, s_mmp_block = 0x168, s_raid_stripe_width = 0x170, s_log_groups_per_flex = 0x174, s_checksum_type = 0x175, s_encryption_level = 0x176, s_reserved_pad = 0x177, s_kbytes_written = 0x178, s_snapshot_inum = 0x180, s_snapshot_id = 0x184, s_snapshot_r_blocks_count = 0x188, s_snapshot_list = 0x190, s_error_count = 0x194, s_first_error_time = 0x198, s_first_error_ino = 0x19c, s_first_error_block = 0x1a0, s_first_error_func = 0x1a8, s_first_error_line = 0x1c8, s_last_error_time = 0x1cc, s_last_error_ino = 0x1d0, s_last_error_line = 0x1d4, s_last_error_block = 0x1d8, s_last_error_func = 0x1e0, s_mount_opts = 0x200, s_usr_quota_inum = 0x240, s_grp_quota_inum = 0x244, s_overhead_clusters = 0x248, s_backup_bgs = 0x24c, s_encrypt_algos = 0x254, s_encrypt_pw_salt = 0x258, s_lpf_ino = 0x268, s_prj_quota_inum = 0x26c, s_checksum_seed = 0x270, s_reserved = 0x274, s_checksum = 0x3fc);

/// ext4 block group descriptor (64-byte form)
#[repr(C, packed)]
pub struct ext4_group_desc {
    pub bg_block_bitmap_lo: u32,
    pub bg_inode_bitmap_lo: u32,
    pub bg_inode_table_lo: u32,
    pub bg_free_blocks_count_lo: u16,
    pub bg_free_inodes_count_lo: u16,
    pub bg_used_dirs_count_lo: u16,
    pub bg_flags: u16,
    pub bg_exclude_bitmap_lo: u32,
    pub bg_block_bitmap_csum_lo: u16,
    pub bg_inode_bitmap_csum_lo: u16,
    pub bg_itable_unused_lo: u16,
    pub bg_checksum: u16,
    /// from here on: 64bit only
    pub bg_block_bitmap_hi: u32,
    pub bg_inode_bitmap_hi: u32,
    pub bg_inode_table_hi: u32,
    pub bg_free_blocks_count_hi: u16,
    pub bg_free_inodes_count_hi: u16,
    pub bg_used_dirs_count_hi: u16,
    pub bg_itable_unused_hi: u16,
    pub bg_exclude_bitmap_hi: u32,
    pub bg_block_bitmap_csum_hi: u16,
    pub bg_inode_bitmap_csum_hi: u16,
    pub bg_reserved: u32,
}
layout!(ext4_group_desc, 64; bg_block_bitmap_lo = 0x00, bg_inode_bitmap_lo = 0x04, bg_inode_table_lo = 0x08, bg_free_blocks_count_lo = 0x0c, bg_free_inodes_count_lo = 0x0e, bg_used_dirs_count_lo = 0x10, bg_flags = 0x12, bg_exclude_bitmap_lo = 0x14, bg_block_bitmap_csum_lo = 0x18, bg_inode_bitmap_csum_lo = 0x1a, bg_itable_unused_lo = 0x1c, bg_checksum = 0x1e, bg_block_bitmap_hi = 0x20, bg_inode_bitmap_hi = 0x24, bg_inode_table_hi = 0x28, bg_free_blocks_count_hi = 0x2c, bg_free_inodes_count_hi = 0x2e, bg_used_dirs_count_hi = 0x30, bg_itable_unused_hi = 0x32, bg_exclude_bitmap_hi = 0x34, bg_block_bitmap_csum_hi = 0x38, bg_inode_bitmap_csum_hi = 0x3a, bg_reserved = 0x3c);

/// ext4 inode (the first 128 bytes, "good old" size)
#[repr(C, packed)]
pub struct ext4_inode {
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size_lo: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks_lo: u32,
    pub i_flags: u32,
    pub i_osd1: u32,
    /// starts with an ext4_extent_header
    pub i_block: [u8; 60],
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_high: u32,
    pub i_obso_faddr: u32,
    pub i_osd2: [u8; 12],
}
layout!(ext4_inode, 128; i_mode = 0x00, i_uid = 0x02, i_size_lo = 0x04, i_atime = 0x08, i_ctime = 0x0c, i_mtime = 0x10, i_dtime = 0x14, i_gid = 0x18, i_links_count = 0x1a, i_blocks_lo = 0x1c, i_flags = 0x20, i_osd1 = 0x24, i_block = 0x28, i_generation = 0x64, i_file_acl_lo = 0x68, i_size_high = 0x6c, i_obso_faddr = 0x70, i_osd2 = 0x74);

/// ext4 extent tree header (at the start of i_block)
#[repr(C, packed)]
pub struct ext4_extent_header {
    pub eh_magic: u16,
    pub eh_entries: u16,
    pub eh_max: u16,
    pub eh_depth: u16,
    pub eh_generation: u32,
}
layout!(ext4_extent_header, 12; eh_magic = 0, eh_entries = 2, eh_max = 4, eh_depth = 6, eh_generation = 8);

/// ISO 9660 directory record
#[repr(C, packed)]
pub struct iso_directory_record {
    pub length: u8,
    pub ext_attr_length: u8,
    pub extent_le: u32,
    pub extent_be: u32,
    pub data_length_le: u32,
    pub data_length_be: u32,
    pub recording_date: [u8; 7],
    /// ISO_FLAG_*
    pub file_flags: u8,
    pub file_unit_size: u8,
    pub interleave_gap: u8,
    pub volume_sequence_number_le: u16,
    pub volume_sequence_number_be: u16,
    pub name_length: u8,
    /// the root's: one byte, 0 ("." )
    pub name: [u8; 1],
}
layout!(iso_directory_record, 34; length = 0, ext_attr_length = 1, extent_le = 2, extent_be = 6, data_length_le = 10, data_length_be = 14, recording_date = 18, file_flags = 25, file_unit_size = 26, interleave_gap = 27, volume_sequence_number_le = 28, volume_sequence_number_be = 30, name_length = 32, name = 33);

/// ISO 9660 primary volume descriptor (ECMA-119 8.4)
#[repr(C, packed)]
pub struct iso_primary_volume_descriptor {
    /// ISO_VD_PRIMARY
    pub r#type: u8,
    /// "CD001"
    pub id: [u8; 5],
    pub version: u8,
    pub unused1: u8,
    pub system_id: [u8; 32],
    pub volume_id: [u8; 32],
    pub unused2: [u8; 8],
    pub volume_space_size_le: u32,
    pub volume_space_size_be: u32,
    pub unused3: [u8; 32],
    pub volume_set_size_le: u16,
    pub volume_set_size_be: u16,
    pub volume_sequence_number_le: u16,
    pub volume_sequence_number_be: u16,
    pub logical_block_size_le: u16,
    pub logical_block_size_be: u16,
    pub path_table_size_le: u32,
    pub path_table_size_be: u32,
    pub type_l_path_table: u32,
    pub opt_type_l_path_table: u32,
    pub type_m_path_table: u32,
    pub opt_type_m_path_table: u32,
    /// struct iso_directory_record
    pub root_directory_record: [u8; 34],
    pub volume_set_id: [u8; 128],
    pub publisher_id: [u8; 128],
    pub preparer_id: [u8; 128],
    pub application_id: [u8; 128],
    pub copyright_file_id: [u8; 37],
    pub abstract_file_id: [u8; 37],
    pub bibliographic_file_id: [u8; 37],
    pub creation_date: [u8; 17],
    pub modification_date: [u8; 17],
    pub expiration_date: [u8; 17],
    pub effective_date: [u8; 17],
    pub file_structure_version: u8,
    pub unused4: u8,
    pub application_use: [u8; 512],
    pub reserved: [u8; 653],
}
layout!(iso_primary_volume_descriptor, 2048; r#type = 0, id = 1, version = 6, unused1 = 7, system_id = 8, volume_id = 40, unused2 = 72, volume_space_size_le = 80, volume_space_size_be = 84, unused3 = 88, volume_set_size_le = 120, volume_set_size_be = 122, volume_sequence_number_le = 124, volume_sequence_number_be = 126, logical_block_size_le = 128, logical_block_size_be = 130, path_table_size_le = 132, path_table_size_be = 136, type_l_path_table = 140, opt_type_l_path_table = 144, type_m_path_table = 148, opt_type_m_path_table = 152, root_directory_record = 156, volume_set_id = 190, publisher_id = 318, preparer_id = 446, application_id = 574, copyright_file_id = 702, abstract_file_id = 739, bibliographic_file_id = 776, creation_date = 813, modification_date = 830, expiration_date = 847, effective_date = 864, file_structure_version = 881, unused4 = 882, application_use = 883, reserved = 1395);

// ---- constants (pg_layout.h) ------------------------------------------------

/// NTFS, FAT and MBR boot sectors.
pub const BOOT_SIGNATURE: u64 = 0xaa55;
pub const NTFS_OEM_ID: &[u8] = b"NTFS    ";
/// Byte-sized counts above this are negative: a power-of-two exponent.
pub const NTFS_BS_NEGATIVE: u64 = 0x80;
/// 2^-v sectors per cluster at most.
pub const NTFS_BS_MAX_CLUSTER_SHIFT: u64 = 20;
/// 2^-v bytes per record at most.
pub const NTFS_BS_MAX_RECORD_SHIFT: u64 = 12;

pub const NTFS_RECORD_MAGIC: &[u8] = b"FILE";
/// The update-sequence array follows the 3.1 header; 3.0's (0x2a) refused.
pub const NTFS_USA_OFFSET_31: u64 = 0x30;
pub const NTFS_RECORD_IN_USE: u64 = 0x0001;
pub const NTFS_RECORD_IS_DIRECTORY: u64 = 0x0002;
/// An MFT reference: 48-bit record number, 16-bit sequence number.
pub const NTFS_MFT_REF_RECORD_MASK: u64 = 0xffff_ffff_ffff;
pub const NTFS_MFT_REF_SEQ_SHIFT: u64 = 48;

pub const NTFS_AT_ATTRIBUTE_LIST: u64 = 0x20;
pub const NTFS_AT_VOLUME_INFORMATION: u64 = 0x70;
pub const NTFS_AT_DATA: u64 = 0x80;
pub const NTFS_AT_END: u64 = 0xffff_ffff;
pub const NTFS_ATTR_COMPRESSION_MASK: u64 = 0x00ff;
pub const NTFS_ATTR_IS_ENCRYPTED: u64 = 0x4000;
pub const NTFS_ATTR_IS_SPARSE: u64 = 0x8000;
/// Mapping pairs: each run's header byte is offset size << 4 | length size.
pub const NTFS_RUN_LENGTH_SIZE_MASK: u64 = 0x0f;
pub const NTFS_RUN_OFFSET_SIZE_SHIFT: u64 = 4;
pub const NTFS_RUN_MAX_FIELD: u64 = 8;
/// `$Volume`.
pub const NTFS_MFT_RECORD_VOLUME: u64 = 3;

pub const GPT_SIGNATURE: &[u8] = b"EFI PART";
/// What one sector read holds.
pub const GPT_MAX_HEADER_SIZE: u64 = 512;
pub const GPT_MAX_ENTRIES: u64 = 1024;
/// EFI System Partition, C12A7328-F81F-11D2-BA4B-00A0C93EC93B, as stored.
pub const GPT_ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
/// IEEE 802.3, reflected.
pub const CRC32_POLY: u32 = 0xedb8_8320;

/// `fat16_boot_sector.fs_type` prefix.
pub const FAT_FS_TYPE: &[u8] = b"FAT";
/// `fat32_boot_sector.fs_type` prefix.
pub const FAT32_FS_TYPE: &[u8] = b"FAT32";

/// Bytes into the filesystem.
pub const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
pub const EXT4_SUPER_MAGIC: u64 = 0xef53;
pub const EXT4_EXT_MAGIC: u64 = 0xf30a;
/// Feature words and `s_inode_size` exist from this revision on.
pub const EXT4_DYNAMIC_REV: u64 = 1;
pub const EXT4_GOOD_OLD_INODE_SIZE: u64 = 128;
/// 1024 << 6 = 64 KiB.
pub const EXT4_MAX_LOG_BLOCK_SIZE: u64 = 6;
pub const EXT4_MIN_DESC_SIZE: u64 = 32;
pub const EXT4_MIN_DESC_SIZE_64BIT: u64 = 64;
pub const EXT4_MAX_DESC_SIZE: u64 = 1024;
pub const EXT4_FEATURE_COMPAT_SPARSE_SUPER2: u64 = 0x0200;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u64 = 0x0080;
pub const EXT4_ROOT_INO: u64 = 2;
pub const EXT4_S_IFMT: u64 = 0xf000;
pub const EXT4_S_IFDIR: u64 = 0x4000;

/// The system area: 16 sectors of 2048.
pub const ISO_PVD_OFFSET: u64 = 32768;
pub const ISO_VD_PRIMARY: u64 = 1;
pub const ISO_STANDARD_ID: &[u8] = b"CD001";
pub const ISO_VD_VERSION: u64 = 1;
pub const ISO_FLAG_DIRECTORY: u64 = 0x02;

// ---- NTFS directory indexes (Rust only: the loader's ntfs::dir) -------------

/// `$INDEX_ROOT` value: what is indexed, then an index header.
#[repr(C, packed)]
pub struct ntfs_index_root {
    pub r#type: u32,
    pub collation_rule: u32,
    pub index_block_size: u32,
    pub clusters_per_index_block: u8,
    pub reserved: [u8; 3],
    /// `ntfs_index_header`
    pub index: [u8; 16],
}
layout!(ntfs_index_root, 0x20; r#type = 0x00, collation_rule = 0x04, index_block_size = 0x08, clusters_per_index_block = 0x0c, reserved = 0x0d, index = 0x10);

/// Index node header (in `$INDEX_ROOT` and in each `INDX` block).
#[repr(C, packed)]
pub struct ntfs_index_header {
    pub entries_offset: u32,
    pub index_length: u32,
    pub allocated_size: u32,
    /// `NTFS_INDEX_LARGE`
    pub flags: u8,
    pub reserved: [u8; 3],
}
layout!(ntfs_index_header, 0x10; entries_offset = 0x00, index_length = 0x04, allocated_size = 0x08, flags = 0x0c, reserved = 0x0d);

/// `INDX` block header (`$INDEX_ALLOCATION`), then an index header.
#[repr(C, packed)]
pub struct ntfs_index_block {
    pub magic: [u8; 4],
    pub usa_offset: u16,
    pub usa_count: u16,
    pub lsn: u64,
    pub index_block_vcn: u64,
    /// `ntfs_index_header`
    pub index: [u8; 16],
}
layout!(ntfs_index_block, 0x28; magic = 0x00, usa_offset = 0x04, usa_count = 0x06, lsn = 0x08, index_block_vcn = 0x10, index = 0x18);

/// Index entry header; a `$FILE_NAME` key follows, a child VCN ends it.
#[repr(C, packed)]
pub struct ntfs_index_entry {
    pub indexed_file: u64,
    pub length: u16,
    pub key_length: u16,
    /// `NTFS_INDEX_ENTRY_*`
    pub flags: u16,
    pub reserved: u16,
}
layout!(ntfs_index_entry, 0x10; indexed_file = 0x00, length = 0x08, key_length = 0x0a, flags = 0x0c, reserved = 0x0e);

/// `$FILE_NAME` value (an index key); the UTF-16 name follows.
#[repr(C, packed)]
pub struct ntfs_file_name {
    pub parent_directory: u64,
    pub creation_time: u64,
    pub last_data_change_time: u64,
    pub last_mft_change_time: u64,
    pub last_access_time: u64,
    pub allocated_size: u64,
    pub data_size: u64,
    /// `NTFS_FILE_ATTR_*`
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub file_name_length: u8,
    pub file_name_type: u8,
}
layout!(ntfs_file_name, 0x42; parent_directory = 0x00, creation_time = 0x08, last_data_change_time = 0x10, last_mft_change_time = 0x18, last_access_time = 0x20, allocated_size = 0x28, data_size = 0x30, file_attributes = 0x38, reparse_tag = 0x3c, file_name_length = 0x40, file_name_type = 0x41);

pub const NTFS_AT_FILE_NAME: u64 = 0x30;
pub const NTFS_AT_INDEX_ROOT: u64 = 0x90;
pub const NTFS_AT_INDEX_ALLOCATION: u64 = 0xa0;
pub const NTFS_AT_BITMAP: u64 = 0xb0;
pub const NTFS_COLLATION_FILE_NAME: u64 = 1;
pub const NTFS_INDEX_MAGIC: &[u8] = b"INDX";
/// `ntfs_index_header.flags`: the node has children (an allocation).
pub const NTFS_INDEX_LARGE: u64 = 1;
pub const NTFS_INDEX_ENTRY_NODE: u64 = 1;
pub const NTFS_INDEX_ENTRY_END: u64 = 2;
/// `file_attributes`: a directory (its record carries an `$I30` index).
pub const NTFS_FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT: u64 = 0x1000_0000;
/// `file_attributes`: a reparse point (junction, symlink…).
pub const NTFS_FILE_ATTR_REPARSE_POINT: u64 = 0x0400;
