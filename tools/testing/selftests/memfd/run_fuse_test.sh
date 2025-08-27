#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

trap 'umount_mnt' EXIT

umount_mnt(){
	if test -d "./mnt" ; then
		fusermount -u ./mnt
		rmdir ./mnt
	fi
}

umount_mnt

set -e

mkdir mnt
./fuse_mnt ./mnt
./fuse_test ./mnt/memfd $@
fusermount -u ./mnt
rmdir ./mnt
