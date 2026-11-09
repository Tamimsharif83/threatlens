#!/usr/bin/env bash
# Download public attack datasets for trying ThreatLens rules on real attack logs.
#
#   scripts/fetch-datasets.sh            # both datasets into ./datasets/
#   scripts/fetch-datasets.sh evtx       # only EVTX-ATTACK-SAMPLES (~40 MB)
#   scripts/fetch-datasets.sh otrf       # only the OTRF Windows subset (~60 MB)
#   DATASETS_DIR=/somewhere scripts/fetch-datasets.sh
#
# Nothing here is redistributed by ThreatLens: the files land in ./datasets/,
# which is git-ignored, and each keeps its own licence file next to it.
#
# | Dataset                                   | Licence  | What it is                       |
# |-------------------------------------------|----------|----------------------------------|
# | sbousseaden/EVTX-ATTACK-SAMPLES           | GPL-3.0  | ~270 .evtx files, by ATT&CK tactic |
# | OTRF/Security-Datasets (Windows atomic)   | MIT      | zipped JSON from recorded attacks |
#
# Both are pinned to a commit so the files you test with today are the files
# you test with next year. Then, for example:
#
#   docker compose cp "datasets/EVTX-ATTACK-SAMPLES/Credential Access" threatlens:/data/inbox/evtx-cred
#   # or: threatlens ingest datasets/EVTX-ATTACK-SAMPLES        (from a checkout)
#
# OTRF files are zipped JSON with Windows field names at the top level; upload the
# .zip files as they are: they are recognised as Windows events (parser `evtx`).
set -euo pipefail

EVTX_REPO="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git"
EVTX_COMMIT="4ceed2f4706daf601c212a8f91c113dd85349a2c"   # 2023-01-24
OTRF_REPO="https://github.com/OTRF/Security-Datasets.git"
OTRF_COMMIT="d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"   # 2023-09-20
# The full OTRF repository is ~800 MB; take the Windows host datasets for these tactics.
OTRF_PATHS=(
  "datasets/atomic/windows/credential_access/host"
  "datasets/atomic/windows/lateral_movement/host"
  "datasets/atomic/windows/execution/host"
)

DEST="${DATASETS_DIR:-$(cd "$(dirname "$0")/.." && pwd)/datasets}"
WHAT="${1:-all}"

die() { echo "error: $*" >&2; exit 1; }
command -v git >/dev/null || die "git is required"

# Shallow, blob-less, sparse clone of exactly one commit.
fetch() {
  local repo="$1" commit="$2" dir="$3"; shift 3
  if [[ -d "$dir/.git" ]] && [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$commit" ]]; then
    echo "already there: $dir"
    return
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" remote add origin "$repo"
  git -C "$dir" config core.protectNTFS true      # refuse odd paths, also on Linux
  git -C "$dir" config core.symlinks false        # a dataset never needs a symlink
  if (($#)); then
    git -C "$dir" sparse-checkout set --no-cone "$@" "LICENSE*" "README*"
  fi
  git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$commit"
  git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
  rm -rf "$dir/.git/hooks"
  echo "fetched $(du -sh "$dir" | cut -f1) into $dir ($(find "$dir" -type f -not -path '*/.git/*' | wc -l) files)"
}

case "$WHAT" in
  all|evtx|otrf) ;;
  *) die "unknown dataset '$WHAT' (use: all, evtx, otrf)" ;;
esac

mkdir -p "$DEST"
if [[ "$WHAT" == all || "$WHAT" == evtx ]]; then
  fetch "$EVTX_REPO" "$EVTX_COMMIT" "$DEST/EVTX-ATTACK-SAMPLES"
fi
if [[ "$WHAT" == all || "$WHAT" == otrf ]]; then
  fetch "$OTRF_REPO" "$OTRF_COMMIT" "$DEST/Security-Datasets" "${OTRF_PATHS[@]/#//}"
fi

cat <<EOF

Done. Licences: EVTX-ATTACK-SAMPLES is GPL-3.0 (see its LICENSE.GPL),
OTRF Security-Datasets is MIT (see its LICENSE). Keep them out of git:
$DEST is ignored by ThreatLens' .gitignore.
EOF
