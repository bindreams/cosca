#!/usr/bin/env bash
# THROWAWAY (tmp PR): K5 proofs on Windows.
set -u
T="$1"
SEL='[.["rust-suites"][] | .["binary-id"] as $b | .testcases | to_entries[] | select(.value["filter-match"].status == "matches") | [$b, .key]] | sort'
ALL='[.["rust-suites"][] | .["binary-id"] as $b | .testcases | to_entries[] | [$b, .key, .value.ignored, .value["filter-match"].status]] | sort'
NAME=a_drive_relative_current_dir_takes_the_drives_own_directory_as_win32_does
list() { cargo nextest list --locked --target "$T" --test windows_process_cwd --message-format json "$@" 2>/dev/null; }
echo "##### PROOF1 old lane (no labels, -E name)"; list -E "test(=$NAME)" | jq -S -c "$SEL"
echo "##### PROOF1 GREEN new lane (SKULD_LABELS=drive_mapping)"; SKULD_LABELS=drive_mapping list | jq -S -c "$SEL"
echo "##### PROOF2 GREEN main lane (=0)"; COSCA_TEST_DRIVE_MAPPING=0 list | jq -S -c "$ALL"
echo "##### PROOF2 RED main lane (var unset, as before the opt-out)"; env -u COSCA_TEST_DRIVE_MAPPING cargo nextest list --locked --target "$T" --test windows_process_cwd --message-format json 2>/dev/null | jq -S -c "$ALL"
PIN='test(/^drive_mapping_|the_drive_mapping_label_selects_its_test/)'
run() { cargo nextest run --locked --target "$T" --test windows_process_cwd --no-fail-fast --no-capture -E "$PIN" 2>&1; }
echo "##### TESTS GREEN"; env -u COSCA_TEST_DRIVE_MAPPING run | grep -E "PASS|FAIL|Summary"
echo "##### MUTANT no label"; sed -i 's/, labels = \[crate::test_harness::\$label\]//' src/test_groups.rs; git diff --stat src; 
echo "##### PROOF1 RED (label mutant)"; SKULD_LABELS=drive_mapping list | jq -S -c "$SEL"
env -u COSCA_TEST_DRIVE_MAPPING run | grep -E "PASS|FAIL|Summary"; git checkout -- src
echo "##### MUTANT requires never fails"; sed -i 's/requires = \[\$fixture::enabled\], //' src/test_groups.rs; git diff --stat src
env -u COSCA_TEST_DRIVE_MAPPING run | grep -E "PASS|FAIL|Summary"; git checkout -- src
echo "##### MUTANT no consent check"; sed -i 's/!= Some("1")/== Some("zzz")/' src/test_groups.rs; git diff --stat src
env -u COSCA_TEST_DRIVE_MAPPING run | grep -E "PASS|FAIL|Summary"; git checkout -- src
echo "##### DONE"
