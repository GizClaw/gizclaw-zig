#!/usr/bin/env bash
set -euo pipefail

text="hello from gizclaw zig workspace test"
out_file=""
keep_audio=0

usage() {
  cat <<'EOF'
usage: make-opus-packets.sh --out FILE [options]

Generate a real speech Opus packet fixture for workspace conversation smoke.

Options:
  --out FILE       Output file: one base64-encoded Opus packet per line
  --text TEXT      Speech text to synthesize
  --keep-audio     Keep sibling .aiff and .ogg files next to the output
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      out_file="$2"
      shift 2
      ;;
    --text)
      text="$2"
      shift 2
      ;;
    --keep-audio)
      keep_audio=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$out_file" ]]; then
  echo "missing required --out" >&2
  usage >&2
  exit 2
fi
if ! command -v say >/dev/null 2>&1; then
  echo "macOS say command is required" >&2
  exit 2
fi
if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg is required" >&2
  exit 2
fi

mkdir -p "$(dirname "$out_file")"
base="${out_file%.*}"
aiff="$base.aiff"
ogg="$base.ogg"

say -o "$aiff" "$text"
ffmpeg -hide_banner -loglevel error -y \
  -i "$aiff" \
  -ac 1 \
  -ar 16000 \
  -c:a libopus \
  -application voip \
  -frame_duration 20 \
  "$ogg"

python3 - "$ogg" "$out_file" <<'PY'
import base64
import pathlib
import sys

ogg_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
data = ogg_path.read_bytes()
offset = 0
pending = bytearray()
packets = []

while offset < len(data):
    if offset + 27 > len(data) or data[offset:offset + 4] != b"OggS":
        raise SystemExit(f"invalid Ogg page at byte {offset}")
    segment_count = data[offset + 26]
    lacing_start = offset + 27
    lacing_end = lacing_start + segment_count
    if lacing_end > len(data):
        raise SystemExit("truncated Ogg lacing table")
    lacing = data[lacing_start:lacing_end]
    body_len = sum(lacing)
    body_start = lacing_end
    body_end = body_start + body_len
    if body_end > len(data):
        raise SystemExit("truncated Ogg page body")
    body = data[body_start:body_end]
    cursor = 0
    for size in lacing:
        pending.extend(body[cursor:cursor + size])
        cursor += size
        if size < 255:
            packet = bytes(pending)
            pending.clear()
            if packet and not packet.startswith(b"OpusHead") and not packet.startswith(b"OpusTags"):
                packets.append(packet)
    offset = body_end

if pending:
    raise SystemExit("unterminated Ogg packet")
if not packets:
    raise SystemExit("no Opus payload packets found")

out_path.write_text("\n".join(base64.b64encode(packet).decode("ascii") for packet in packets) + "\n")
print(f"wrote {len(packets)} Opus packets to {out_path}")
PY

if [[ "$keep_audio" != "1" ]]; then
  rm -f "$aiff" "$ogg"
fi
