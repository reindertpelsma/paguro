#!/bin/sh
# On a paguro boot the root is whatever paguro-initrd builds, always
# shellcheck disable=SC2034  # root, rootok: read by dracut
# linked at /dev/paguro-root: `root=paguro` or no root= at all.
if [ -z "$root" ] || [ "$root" = "paguro" ]; then
    st=$(paguro-initrd systab 2> /dev/null) || return 0
    modprobe -q paguro-handoff systab="$st" 2> /dev/null || return 0
    root="block:/dev/paguro-root"
    rootok=1
fi
