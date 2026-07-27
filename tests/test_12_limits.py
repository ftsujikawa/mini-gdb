"""
04_テスト仕様書.md 12章「非機能（制限値）テスト」(T-100~T-103)。

T-101~T-103は専用のテストプログラム（`tests/fixtures/`、それぞれ
`dbg.h`/`heap.c`の固定上限を実際に超える規模で書かれている）を用いる:
  - big_struct.c    構造体メンバ20個（`type_info_t.members[16]`超過）
  - heap_stress.c   4200回の`malloc`（`MAX_HEAP_ALLOCS`=4096超過）
  - many_symbols.c  関数1100個（`MAX_SYMBOLS`=1024超過）
"""
import os
import subprocess

from harness import ROOT, check, check_contains, check_regex, extract, run_scenario

FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def _build(name):
    src = os.path.join(FIXTURES, name + ".c")
    binpath = os.path.join(FIXTURES, name)
    subprocess.run(["gcc", "-g", "-O0", src, "-o", binpath], check=True)
    return os.path.relpath(binpath, ROOT)


def run(r):
    try:
        big_struct = _build("big_struct")
        heap_stress = _build("heap_stress")
        many_symbols = _build("many_symbols")
    except Exception as e:
        r.results.append(("T-101/102/103", "ERROR", "failed to build fixtures: %r" % e))
        r.step("T-100", "ブレークポイント上限", _t100)
        return

    run_scenario(r, [("T-100", "ブレークポイント上限", _t100)])
    run_scenario(r, [("T-101", "構造体メンバ上限", lambda s: _t101(s, big_struct))])
    run_scenario(r, [("T-102", "ヒープ確保記録上限", lambda s: _t102(s, heap_stress))])
    run_scenario(r, [("T-103", "シンボル数上限規模のバイナリ", lambda s: _t103(s, many_symbols))])


def _t100(s):
    s.cmd("run target")
    out = s.cmd("syms")
    main_addr = int(extract(out, r"(0x[0-9a-f]+)\s+\d+\s+func\s+main", label="T-100"), 16)
    last = ""
    for i in range(33):
        last = s.cmd("b 0x%x" % (main_addr + i * 4))
    check_contains(last, "too many breakpoints", "T-100 (33rd rejected)")
    out = s.cmd("show bp")
    # "show bp\r\n" (echo) + header row + up to 32 data rows.
    n_data_rows = out.count("\n") - 2
    check(n_data_rows <= 32, "T-100: show bp should list at most 32 entries, got %d:\n%s"
          % (n_data_rows, out[:200]))


def _t101(s, big_struct):
    s.cmd("run " + big_struct)
    s.cmd("b big_struct.c:21")
    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-101 setup")
    out = s.cmd("p b")
    check_not_crashed(s)
    check_contains(out, "m16 = 16", "T-101 (16th member shown)")
    check("m17" not in out, "T-101 (17th+ member must not appear): %s" % out)


def check_not_crashed(s):
    check(s.proc.poll() is None, "tdb process must still be alive (not crashed)")


def _t102(s, heap_stress):
    s.cmd("set heap-trace on")
    s.cmd("run " + heap_stress)
    out = s.cmd("c", timeout=15)
    check_contains(out, "process exited", "T-102 (ran to completion, no crash)")
    check_regex(out, r"\[heap\] (\d+) leak\(s\) at process exit", "T-102")
    out = s.cmd("show leaks")
    m = check_regex(out, r"(\d+) leak\(s\)", "T-102")
    count = int(m.group(1))
    check(count <= 4096, "T-102: leak count %d exceeds MAX_HEAP_ALLOCS (4096)" % count)


def _t103(s, many_symbols):
    out = s.cmd("run " + many_symbols)
    check_contains(out, "process started", "T-103 (starts without crashing)")
    out = s.cmd("c", timeout=10)
    check_contains(out, "process exited", "T-103 (runs to completion)")
    out = s.cmd("syms")
    m = check_regex(out, r"(\d+) symbol\(s\)", "T-103")
    count = int(m.group(1))
    check(count <= 1024, "T-103: symbol count %d exceeds MAX_SYMBOLS (1024)" % count)
