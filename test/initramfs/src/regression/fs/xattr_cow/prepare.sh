#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail

test ! -e /out/fixture.ext2
mkdir /out/mnt
mounted=0
cleanup() {
    if (( mounted )); then umount /out/mnt; fi
    rmdir /out/mnt
}
trap cleanup EXIT
truncate -s 32M /out/fixture.ext2
mkfs.ext2 -F -b 4096 /out/fixture.ext2
mount -o loop /out/fixture.ext2 /out/mnt
mounted=1
python3 - <<'PY'
import os
for index in range(8):
    path = f'/out/mnt/file{index}'
    with open(path, 'xb'):
        pass
    os.chmod(path, 0o644)
    os.setxattr(path, 'user.shared', b'x' * 512)
PY
sync
umount /out/mnt
mounted=0
shared_block=""
for index in 0 1 2 3 4 5 6 7; do
    block="$(debugfs -R "stat /file$index" /out/fixture.ext2 2>/dev/null | awk '/^File ACL:/ {print $3}')"
    [[ "$block" =~ ^[0-9]+$ ]] && (( block > 0 ))
    if [[ -z "$shared_block" ]]; then shared_block="$block"; fi
    test "$block" = "$shared_block"
done
references="$(od -An -tu4 -j "$(( shared_block * 4096 + 4 ))" -N4 /out/fixture.ext2)"
(( references == 8 ))
printf 'shared xattr block=%s references=%s\n' "$shared_block" "$references"
e2fsck -fn /out/fixture.ext2
