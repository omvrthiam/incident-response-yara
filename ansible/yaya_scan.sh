#!/bin/bash
YARA_RULE="$1"
SCAN_DIR="/tmp"
OUTPUT="/tmp/yara_results.txt"

if [ ! -f "$YARA_RULE" ]; then
  echo "YARA rule file not found!"
  exit 1
fi

yara "$YARA_RULE" $SCAN_DIR > $OUTPUT 2>/dev/null
cat $OUTPUT
