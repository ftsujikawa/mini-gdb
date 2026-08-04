"""
04_テスト仕様書.md 5a章「ウォッチポイントテスト」(T-19c~T-19m)。

前提どおり `target` を `b main`→`c` でヒットさせた状態
（`target.c:19`、ローカル変数`x,y,ts,ts_ptr,sa,sa_ptr,pm`が有効）から
1つの継続セッションで手順を進める。上限（4個、DR0-DR3制約）に達すると
それ以降の`watch`は式やフラグの妥当性を問わず「too many watchpoints」
になるため、T-19j（未解決の式）とT-19l（不正フラグ）は上限に達する前
（スロットが2個空いている段階）で検証する。
"""
import re

from harness import check, check_contains, check_regex, extract, run_scenario


def run(r):
    run_scenario(r, [
        ("setup", "target: b main -> c", _setup),
        ("T-19c", "設置", _t19c),
        ("T-19d", "一覧表示", _t19d),
        ("T-19j", "未解決の式", _t19j),
        ("T-19l", "不正フラグ", _t19l),
        ("T-19e", "値変化での停止", _t19e),
        ("T-19f", "サイズ自動判定エラー", _t19f),
        ("T-19g", "サイズ明示指定", _t19g),
        ("T-19h", "読み書きアクセス監視", _t19h),
        ("T-19i", "上限超過", _t19i),
        ("T-19k", "削除", _t19k),
        ("T-19m", "プロセス終了時のリセット", _t19m),
    ])


def _setup(s):
    s.cmd("run target")
    s.cmd("b main")
    out = s.cmd("c")
    check_contains(out, "target.c:19", "setup")


def _t19c(s):
    out = s.cmd("watch x")
    check_contains(out, "Hardware watchpoint 1: x", "T-19c")
    out = s.cmd("show watch")
    check_contains(out, "x", "T-19c (registered)")


def _t19d(s):
    out = s.cmd("watch y")
    check_contains(out, "Hardware watchpoint 2: y", "T-19d")
    out = s.cmd("show watch")
    check_regex(out, r"Num\s+Enb\s+Address\s+Size\s+Mode\s+What", "T-19d (header)")
    check_regex(out, r"1\s+y\s+0x[0-9a-f]+\s+4\s+w\s+x", "T-19d (x entry)")
    check_regex(out, r"2\s+y\s+0x[0-9a-f]+\s+4\s+w\s+y", "T-19d (y entry)")


def _t19j(s):
    out = s.cmd("watch nosuchvar")
    check_contains(out, "unknown variable", "T-19j")
    out = s.cmd("show watch")
    check(out.count("\n") <= 4, "T-19j: no new watchpoint should have been registered:\n%s" % out)


def _t19l(s):
    out = s.cmd("watch /9 x")
    check_contains(out, "usage", "T-19l")


def _t19e(s):
    out = s.cmd("c")
    check_contains(out, "Hardware watchpoint 1: x", "T-19e")
    # Old value is whatever uninitialized stack held (non-deterministic);
    # the spec only requires "Old value = ..." to appear.
    check_contains(out, "Old value = ", "T-19e")
    check_contains(out, "New value = 10", "T-19e")


def _t19f(s):
    out = s.cmd("watch ts")
    check_contains(out, "cannot watch value of size 12", "T-19f")


def _t19g(s):
    out = s.cmd("watch /4 ts")
    check_contains(out, "Hardware watchpoint 3: ts", "T-19g")


def _t19h(s):
    out = s.cmd("watch /r pm")
    check_contains(out, "Hardware access (read/write) watchpoint 4: pm", "T-19h")
    # `y` (watched in T-19d) hasn't been written yet either, so it may
    # report first; keep continuing until pm's access watchpoint fires.
    out = ""
    for _ in range(5):
        out = s.cmd("c")
        if "access (read/write) watchpoint" in out:
            break
    check_contains(out, "access (read/write) watchpoint", "T-19h (reported on hit)")


def _t19i(s):
    out = s.cmd("watch sa_ptr")
    check_contains(out, "too many watchpoints", "T-19i")


def _t19k(s):
    out = s.cmd("show watch")
    num = extract(out, r"(\d+)\s+y\s+0x[0-9a-f]+\s+\d+\s+rw\s+pm", label="T-19k")
    out = s.cmd("del w" + num)
    check_contains(out, "Watchpoint %s deleted" % num, "T-19k")
    out = s.cmd("show watch")
    check(re.search(r"\bpm\b", out) is None, "T-19k: pm watchpoint should be gone from show watch:\n%s" % out)
    check_contains(out, "x", "T-19k (remaining watchpoints still listed)")
    check_contains(out, "ts", "T-19k (remaining watchpoints still listed)")


def _t19m(s):
    s.cmd("kill")
    s.cmd("run target")
    out = s.cmd("show watch")
    check_contains(out, "no watchpoints", "T-19m")
    s.cmd("b main")
    s.cmd("c")
    out = s.cmd("watch x")
    check_contains(out, "Hardware watchpoint 1: x", "T-19m (fresh 4-slot budget after new run)")
