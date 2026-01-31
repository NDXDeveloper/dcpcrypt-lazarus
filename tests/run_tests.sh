#!/bin/bash
# Compile and run all DCPcrypt functional tests
set -e

SRCDIR=../src
PASS=0
FAIL=0
TOTAL=0

echo "=== DCPcrypt Functional Test Suite ==="
echo

for test in test_hashes test_ciphers test_block_modes test_base64 test_stream_encrypt; do
  TOTAL=$((TOTAL+1))
  echo ">>> Compiling $test.lpr ..."
  if fpc -Mdelphi -FE. -Fu$SRCDIR -Fu$SRCDIR/Ciphers -Fu$SRCDIR/Hashes -Fu. "$test.lpr" > /dev/null 2>&1; then
    echo ">>> Running $test ..."
    echo
    if ./"$test"; then
      PASS=$((PASS+1))
    else
      FAIL=$((FAIL+1))
    fi
    echo
  else
    echo ">>> COMPILATION FAILED for $test.lpr"
    echo "    Re-running with output:"
    fpc -Mdelphi -FE. -Fu$SRCDIR -Fu$SRCDIR/Ciphers -Fu$SRCDIR/Hashes -Fu. "$test.lpr" || true
    FAIL=$((FAIL+1))
    echo
  fi
done

echo "=== Suite Summary: $PASS/$TOTAL passed, $FAIL failed ==="
if [ $FAIL -ne 0 ]; then
  exit 1
fi
exit 0
