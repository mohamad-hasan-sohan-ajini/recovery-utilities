#!/usr/bin/env python3
"""Read-only heuristic scanner for surviving ext4 directory entries."""

import argparse
import csv
import os
import stat
import struct
import sys

TYPES = {
    0: "UNKNOWN",
    1: "FILE",
    2: "DIRECTORY",
    3: "CHAR_DEVICE",
    4: "BLOCK_DEVICE",
    5: "FIFO",
    6: "SOCKET",
    7: "SYMLINK",
}


def entry_at(buf, offset, max_inode):
    if offset + 8 > len(buf):
        return None
    # <IHBB means
    # <	Little-endian byte order
    # I	Unsigned 32-bit integer
    # H	Unsigned 16-bit integer
    # B	Unsigned 8-bit integer
    inode, rec_len, name_len, typ = struct.unpack_from("<IHBB", buf, offset)
    if (
        not inode
        or (max_inode and inode > max_inode)
        or typ not in TYPES
        or rec_len < 12
        or rec_len % 4
        or offset + rec_len > len(buf)
        or not (1 <= name_len <= 255)
        or name_len > rec_len - 8
    ):
        return None
    raw = buf[offset + 8 : offset + 8 + name_len]
    if b"\x00" in raw or b"/" in raw:
        return None
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return None
    return inode, rec_len, name, TYPES[typ]


def scan_block(buf, origin, max_inode):
    seen = set()
    for start in range(0, len(buf) - 7, 4):
        first = entry_at(buf, start, max_inode)
        if not first:
            continue
        second = entry_at(buf, start + first[1], max_inode)
        if not second:
            continue
        pos = start
        while pos < len(buf):
            entry = entry_at(buf, pos, max_inode)
            if not entry:
                break
            inode, rec_len, name, kind = entry
            if pos not in seen:
                seen.add(pos)
                if name not in (".", ".."):
                    yield origin + pos, inode, kind, name
            pos += rec_len


def get_size(src):
    try:
        if stat.S_ISBLK(os.stat(src).st_mode):
            import fcntl

            fd = os.open(src, os.O_RDONLY)
            try:
                return struct.unpack("Q", fcntl.ioctl(fd, 0x80081272, b"\0" * 8))[0]
            finally:
                os.close(fd)
        return os.path.getsize(src)
    except OSError:
        return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", help="Ext4 partition device or partition image")
    p.add_argument("-o", "--output", default="recovered_filenames.tsv")
    p.add_argument("-b", "--block-size", type=int, default=4096)
    p.add_argument("--max-inode", type=int)
    p.add_argument(
        "--partition-start",
        type=int,
        default=0,
        help="Partition start byte offset on physical disk (default 0)",
    )
    args = p.parse_args()
    if args.block_size < 1024 or args.block_size % 4:
        p.error("Block size must be >=1024 and divisible by four")
    if args.partition_start < 0:
        p.error("--partition-start must be nonnegative")
    if args.max_inode is not None and args.max_inode < 1:
        p.error("--max-inode must be positive")
    if os.path.realpath(args.source) == os.path.realpath(args.output):
        p.error("Source and output cannot be the same file")
    size = get_size(args.source)
    count = 0
    with open(args.source, "rb", buffering=0) as disk, open(
        args.output, "w", newline="", encoding="utf-8"
    ) as output:
        writer = csv.writer(output, delimiter="\t")
        writer.writerow(
            [
                "directory_entry_offset_partition_bytes",
                "directory_entry_offset_disk_bytes",
                "directory_entry_offset_disk_hex",
                "inode",
                "type",
                "original_filename",
            ]
        )
        processed = 0
        next_report = 1024**3
        while block := disk.read(args.block_size):
            for offset, inode, kind, name in scan_block(
                block,
                processed,
                args.max_inode,
            ):
                disk_offset = args.partition_start + offset
                writer.writerow(
                    [offset, disk_offset, f"0x{disk_offset:X}", inode, kind, name]
                )
                count += 1
            processed += len(block)
            if processed >= next_report:
                progress = f" ({processed / size * 100:.1f}%)" if size else ""
                print(
                    f"Scanned {processed:,} bytes{progress}; candidates: {count}",
                    file=sys.stderr,
                )
                next_report += 1024**3
    print(f"Found {count} candidate entries; saved to {args.output}")
    print("Offsets identify filename directory entries, NOT file-content locations.")


if __name__ == "__main__":
    main()
