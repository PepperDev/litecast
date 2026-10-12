# Aggregate gcov .gcov files into per-source line-coverage percentages.
#
# Usage:
#   awk -f tests/coverage.awk obj/gcov/*.gcov        # print summary, gate=80
#   awk -f tests/coverage.awk -v gate=80 ...         # exit 1 if any src file < 80%
#   awk -f tests/coverage.awk -v gate=80 -v list=1 ... # print only offenders

BEGIN {
    gate = gate + 0;
}

/^[[:space:]]*-+:[[:space:]]*0:Source:/ {
    src = $0;
    sub(/^.*Source:[[:space:]]*/, "", src);
    cur = src;
    next;
}

{
    cnt = $1;
    sub(/:$/, "", cnt);
    if (cnt == "-" || cnt == "=" || cnt == "")
        next;
    total[cur]++;
    if (cnt !~ /^#/)
        exec[cur]++;
}

END {
    bad = 0;
    for (f in total) {
        if (f !~ /src\//)
            continue;
        pct = total[f] ? (100 * exec[f] / total[f]) : 100;
        if (list) {
            if (pct < gate - 0.005)
                printf "%-45s %6.1f%%  (%d/%d)\n", f, pct, exec[f], total[f];
            continue;
        }
        printf "%-45s %6.1f%%  (%d/%d)\n", f, pct, exec[f], total[f];
        if (gate && pct < gate - 0.005)
            bad = 1;
    }
    if (list)
        exit(0);
    if (bad) {
        printf "COVERAGE GATE FAILED below minimum %d%%\n", gate;
        exit(1);
    }
    print "COVERAGE OK";
    exit(0);
}