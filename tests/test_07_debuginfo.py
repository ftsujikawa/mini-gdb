"""
04_テスト仕様書.md 7章「デバッグ情報・ソース表示テスト」(T-40~T-50)。

T-45/T-50は仕様書の例`target.c:27`が現在の`target.c`では空行のため、
6章と同様に`target.c:30`（add呼び出し行）で代替する。
"""
from harness import check, check_contains, check_regex, run_scenario


def run(r):
    run_scenario(r, [
        ("setup", "target: b add -> c", _setup),
        ("T-40", "現在行のソース表示", _t40),
        ("T-41", "行番号指定表示", _t41),
        ("T-42", "file:line指定表示", _t42),
        ("T-43", "関数名指定表示", _t43),
        ("T-44", "逆アセンブル(関数指定)", _t44),
        ("T-45", "逆アセンブル(行指定)", _t45),
        ("T-46", "DWARF変数一覧", _t46),
        ("T-47", "DWARF個別変数", _t47),
        ("T-48", "行番号テーブル全体", _t48),
        ("T-49", "行番号テーブル(ファイル指定)", _t49),
        ("T-50", "DWARF行情報詳細", _t50),
    ])


def _setup(s):
    s.cmd("run target")
    s.cmd("b add")
    out = s.cmd("c")
    check_contains(out, "target.c:13", "setup")


def _t40(s):
    out = s.cmd("l")
    check_contains(out, "target.c:13", "T-40")
    check_regex(out, r"=>\s*13\s+int c = a \+ b;", "T-40 (current line marked)")


def _t41(s):
    out = s.cmd("list 20")
    check_regex(out, r"=>\s*/.*target\.c:20", "T-41")
    check_contains(out, "int y = 20;", "T-41")


def _t42(s):
    out = s.cmd("list target.c:10")
    check_regex(out, r"=>\s*/.*target\.c:10", "T-42")


def _t43(s):
    out = s.cmd("list add")
    check_contains(out, "int add(struct test_struct *ts, int a, int b)", "T-43")


def _t44(s):
    out = s.cmd("dis add")
    check_contains(out, "<add>:", "T-44")
    check_contains(out, "ret", "T-44 (disassembly body present)")


def _t45(s):
    out = s.cmd("dis target.c:30")
    check_contains(out, "call", "T-45 (call to add visible near this line)")


def _t46(s):
    out = s.cmd("dbg vars")
    for name in ("x", "y", "ts", "sa", "pm"):
        check_regex(out, r"\b%s\b" % name, "T-46 (%s listed)" % name)
    check_regex(out, r"\d+ variable\(s\)", "T-46")


def _t47(s):
    out = s.cmd("dbg var x")
    check_contains(out, "Variable: x", "T-47")
    check_contains(out, "Scope:", "T-47")
    check_regex(out, r"Location:\s+fbreg -?\d+", "T-47")


def _t48(s):
    out = s.cmd("lines")
    check_regex(out, r"Address\s+Line\s+File", "T-48 (header)")
    check_contains(out, "target.c", "T-48")


def _t49(s):
    out = s.cmd("lines target.c")
    check_contains(out, "target.c", "T-49")
    check(
        "leak_target.c" not in out and "thread_target.c" not in out,
        "T-49: lines target.c should only list target.c entries:\n%s" % out[:2000],
    )


def _t50(s):
    out = s.cmd("dbg line target.c:30")
    check_regex(out, r"Address:\s+0x[0-9a-f]+", "T-50")
    check_contains(out, "target.c:30", "T-50")
