# Source this file after setting MOGATE_BIN if mogate is not on PATH.
# Example: MOGATE_BIN="$PWD/bin/mogate" source shell/mogate.sh

mogate-inject() {
    "${MOGATE_BIN:-mogate}" run -- "$@"
}

mogate-shell() {
    "${MOGATE_BIN:-mogate}" run -- "${SHELL:-/bin/sh}"
}

mogate-dev() {
    "${MOGATE_BIN:-mogate}" dev -- "$@"
}
