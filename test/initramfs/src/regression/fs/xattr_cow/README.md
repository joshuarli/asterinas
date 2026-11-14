# Shared ext2 attribute regression

Run `prepare.sh` as root inside the pinned Linux development container with
an empty writable directory mounted at `/out`. The script requires loop mounts,
Python 3 and e2fsprogs. It creates `fixture.ext2`, verifies eight references to
one Linux-written attribute block, and requires a clean filesystem check.

Compile `xattr_cow.c` statically with `-pthread`. Attach a private fixture copy
as the guest's second block device and run the binary as root. The binary mounts
`/dev/vdb`, exercises root and UID 1000 operations, and unmounts it.
For the Linux control, pass the fixture's loop-device path as the argument.
Run `e2fsck -fn` on the unmounted private copy after either control.
