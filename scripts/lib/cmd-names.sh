#!/usr/bin/env bash
# renamed_cmd: the name a cmd directory takes when rename-product.sh renames
# the product. It lives apart from that script so a test can call it without
# running a rename.

# renamed_cmd <dir-name> <old-slug> <new-slug> <old-gateway> <new-gateway>
# Prints the directory's new name, or its name when neither old value is in it.
# The name gets one substitution, from the name it has: a second one would read
# the first one's output. The gateway is tried first, as in the content pass,
# because a one-segment slug is a prefix of the gateway's name.
renamed_cmd() {
  local name="$1"
  case "${name}" in
    *"$4"*) name="${name//$4/$5}" ;;
    *"$2"*) name="${name//$2/$3}" ;;
  esac
  printf '%s\n' "${name}"
}
