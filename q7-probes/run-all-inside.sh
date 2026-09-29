#!/bin/sh
# Runs INSIDE a throwaway --privileged --network none container. $1 = probe binary.
set -u
Q=${1:?}
echo "kernel: $(uname -r) arch: $(uname -m)"
U="unshare --pid --fork --mount --propagation private --mount-proc"
cp "$Q" /usr/local/bin/q7suid && chmod 4755 /usr/local/bin/q7suid
echo "=== reuse (ns_last_pid)"; timeout 60 $U "$Q" reuse
echo "=== reuse (natural, per-ns pid_max=1000)"; timeout 120 $U sh -c "echo 1000 > /proc/sys/kernel/pid_max && $Q reuse-natural"
for m in umount overmount pidns emfile multithread leader-exit exec thread-exec sigign; do echo "=== $m"; timeout 60 $U "$Q" $m; done
for opt in hidepid=2 hidepid=invisible hidepid=ptraceable; do for nd in 0 1; do echo "=== hidepid remount $opt C-nondumpable=$nd uid=1000"; timeout 60 $U "$Q" hidepid $opt $nd 1000; done; done
for opt in hidepid=invisible hidepid=ptraceable; do for how in prctl /usr/local/bin/q7suid; do echo "=== hidepid-late $opt $how uid=1000"; timeout 60 $U "$Q" hidepid-late $opt $how 1000; done; done
echo "=== procns-mismatch"; tail -f /dev/null & B=$!; timeout 60 unshare --pid --fork "$Q" procns-mismatch $B; kill $B
