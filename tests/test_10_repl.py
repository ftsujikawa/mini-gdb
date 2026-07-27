"""
04_テスト仕様書.md 10章「REPL・コマンドラインテスト」(T-80~T-84)。
"""
from harness import check, check_contains, check_not_contains, extract, run_scenario


def run(r):
    run_scenario(r, [
        ("T-80", "ヘルプ表示", _t80),
        ("T-82", "空行入力", _t82),
        ("T-83", "未知コマンド", _t83),
        ("T-84", "短縮形/正式名の等価性", _t84),
    ])
    run_scenario(r, [("T-81", "終了", _t81)])


def _t80(s):
    out = s.cmd("help")
    check_contains(out, "Commands:", "T-80")
    for cmd in ("run", "b|break", "watch", "p|print", "set", "threads", "lock", "q"):
        check_contains(out, cmd, "T-80 (%s documented)" % cmd)


def _t82(s):
    out = s.cmd("")
    check_not_contains(out, "unknown command", "T-82")
    out = s.cmd("help")
    check_contains(out, "Commands:", "T-82 (REPL still responsive)")


def _t83(s):
    out = s.cmd("foobar")
    check_contains(out, "unknown command", "T-83")
    out = s.cmd("help")
    check_contains(out, "Commands:", "T-83 (REPL continues)")


def _t84(s):
    s.cmd("run target")
    out1 = s.cmd("b add")
    check_contains(out1, "breakpoint set", "T-84 (b)")
    out2 = s.cmd("break add")
    check_contains(out2, "breakpoint already exists", "T-84 (break resolves same address as b)")

    s.cmd("c")
    out1 = s.cmd("l")
    out2 = s.cmd("list")
    check_contains(out1, "target.c:13", "T-84 (l)")
    check_contains(out2, "target.c:13", "T-84 (list matches l)")

    out_p = s.cmd("p a")
    out_print = s.cmd("print a")
    check_contains(out_p, "a = 10", "T-84 (p, add's own parameter)")
    check_contains(out_print, "a = 10", "T-84 (print matches p)")

    out = s.cmd("show bp")
    num = extract(out, r"(\d+)\s+y\s+0x[0-9a-f]+\s+add", label="T-84")
    out_del = s.cmd("del " + num)
    check_contains(out_del, "Breakpoint %s deleted" % num, "T-84 (del)")

    s.cmd("b add")
    out = s.cmd("show bp")
    num = extract(out, r"(\d+)\s+y\s+0x[0-9a-f]+\s+add", label="T-84")
    out_delete = s.cmd("delete " + num)
    check_contains(out_delete, "Breakpoint %s deleted" % num, "T-84 (delete matches del)")


def _t81(s):
    s.send("q")
    s.proc.wait(timeout=5)
    check(s.proc.returncode == 0, "T-81: expected exit code 0, got %r" % s.proc.returncode)
