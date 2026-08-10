#!/usr/bin/env bash
# Copies the shared web assets out of thingino-image-builder so this site uses the
# same Bootstrap build, the same Montserrat subset and the same icon font rather than
# a lookalike. Run it when the builder updates its copies.
#
#   tools/vendor.sh [path-to-thingino-image-builder]
set -eu
BUILDER="${1:-$HOME/projects/thingino/thingino-image-builder}"
SRC="$BUILDER/web/vendor"
[ -d "$SRC" ] || { echo "no vendor dir at $SRC (pass the builder checkout as \$1)" >&2; exit 1; }
cd "$(dirname "$0")/.."
mkdir -p web/vendor/fonts
for f in bootstrap.min.css bootstrap-icons.min.css montserrat.css; do
	cp -v "$SRC/$f" web/vendor/
done
for f in montserrat-400 montserrat-500 montserrat-600 montserrat-700 bootstrap-icons; do
	cp -v "$SRC/fonts/$f.woff2" web/vendor/fonts/
done
echo "vendored from $BUILDER"
