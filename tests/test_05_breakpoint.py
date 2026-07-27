"""
04_テスト仕様書.md 5章「ブレークポイントテスト」(T-10~T-19b)。

T-12は仕様書の例`target.c:27`が現在の`target.c`では空行(コード無し)に
なっているため、意味的に等価な実コード行`target.c:30`（add呼び出し行）
で代替する。T-15は`main`関数本体（164バイト）内の4バイト間隔アドレス
を33個使う（実際に実行が到達するアドレスではなく、上限チェック専用の
mapped/readableなアドレスとして使う。33個目だけ超過エラーになること
を見るだけで、これらのブレークポイントを`c`で実際にヒットさせはしない）。
"""
import time

from harness import check, check_contains, check_not_contains, check_regex, extract, run_scenario


def run(r):
    run_scenario(r, [
        ("T-10", "アドレス指定設置", _t10),
        ("T-11", "シンボル指定設置", _t11),
        ("T-12", "file:line指定設置", _t12),
        ("T-13", "一覧表示", _t13),
        ("T-14", "ヒットと停止表示", _t14),
    ])
    run_scenario(r, [("T-15", "上限超過", _t15)])
    run_scenario(r, [
        ("T-16", "ブレークポイント削除", _t16),
        ("T-17", "削除後の実行継続", _t17),
    ])
    run_scenario(r, [("T-18", "削除コマンド正式名", _t18)])
    run_scenario(r, [("T-19", "不正番号の削除", _t19)])
    run_scenario(r, [("T-19b", "引数なし削除", _t19b)])


def _t10(s):
    out = s.cmd("run target")
    check_contains(out, "process started", "T-10 setup")
    out = s.cmd("syms")
    add_addr = extract(out, r"(0x[0-9a-f]+)\s+\d+\s+func\s+add", label="T-10 (syms lookup)")
    out = s.cmd("b " + add_addr)
    check_contains(out, "breakpoint set", "T-10")
    out = s.cmd("show bp")
    check_contains(out, "add", "T-10 (registered, shown in show bp)")


def _t11(s):
    # T-10 set a raw-address breakpoint at add's ELF symbol entry
    # (before prologue skip); `b add` resolves to a *different*,
    # prologue-skipped address, so this is expected to succeed as a
    # second, distinct breakpoint rather than collide with T-10's.
    out = s.cmd("b add")
    check_contains(out, "breakpoint set", "T-11")
    out = s.cmd("show bp")
    check_contains(out, "add+0x", "T-11 (show bp resolves symbol name+offset, i.e. past the prologue)")


def _t12(s):
    out = s.cmd("b target.c:30")
    check_contains(out, "breakpoint set", "T-12")
    out = s.cmd("show bp")
    check_contains(out, "target.c:30", "T-12 (show bp resolves file:line)")


def _t13(s):
    out = s.cmd("show bp")
    check_regex(out, r"Num\s+Enb\s+Address\s+What", "T-13 (header)")
    # Two breakpoints set so far in this scenario (T-10's addr-based one
    # coincides with add's entry; T-12's file:line one).
    lines = [l for l in out.splitlines() if l.strip() and l.strip()[0].isdigit()]
    check(len(lines) >= 2, "T-13: expected >=2 breakpoints listed, got:\n%s" % out)


def _t14(s):
    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-14")
    check_contains(out, "target.c", "T-14 (source line shown)")


def _t15(s):
    out = s.cmd("run target")
    check_contains(out, "process started", "T-15 setup")
    out = s.cmd("syms")
    main_addr = int(extract(out, r"(0x[0-9a-f]+)\s+\d+\s+func\s+main", label="T-15"), 16)

    last_out = ""
    for i in range(33):
        addr = main_addr + i * 4
        last_out = s.cmd("b 0x%x" % addr)
        if i < 32:
            check_contains(last_out, "breakpoint set", "T-15 (breakpoint #%d should succeed)" % (i + 1))
        else:
            check_contains(last_out, "too many breakpoints", "T-15 (33rd breakpoint should be rejected)")


def _t16(s):
    s.cmd("run target")
    s.cmd("b add")
    out = s.cmd("show bp")
    num = extract(out, r"(\d+)\s+y\s+0x[0-9a-f]+\s+add", label="T-16")
    out = s.cmd("del " + num)
    check_contains(out, "Breakpoint %s deleted" % num, "T-16")
    out = s.cmd("show bp")
    check_contains(out, "no breakpoints", "T-16 (entry removed)")


def _t17(s):
    s.send("c")
    time.sleep(1.0)
    s.interrupt()
    out = s.expect(r"\(tdb\) ", timeout=5)
    check_not_contains(out, "breakpoint hit", "T-17 (deleted breakpoint must not fire)")
    check_contains(out, "stopped signal=2", "T-17 (still running until our own interrupt)")


def _t18(s):
    s.cmd("run target")
    s.cmd("b add")
    out = s.cmd("show bp")
    num = extract(out, r"(\d+)\s+y\s+0x[0-9a-f]+\s+add", label="T-18")
    out = s.cmd("delete " + num)
    check_contains(out, "Breakpoint %s deleted" % num, "T-18 (delete == del)")
    out = s.cmd("show bp")
    check_contains(out, "no breakpoints", "T-18")


def _t19(s):
    s.cmd("run target")
    out = s.cmd("del 999")
    check_regex(out, r"(invalid|no such|error)", "T-19", )
    out = s.cmd("b add")
    check_contains(out, "breakpoint set", "T-19 (REPL still responsive after bad delete)")


def _t19b(s):
    s.cmd("run target")
    out = s.cmd("del")
    check_regex(out, r"usage", "T-19b")
