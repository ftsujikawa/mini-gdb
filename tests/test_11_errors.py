"""
04_テスト仕様書.md 11章「異常系テスト」(T-90~T-97)。
"""
from harness import check_contains, check_regex, run_scenario


def run(r):
    run_scenario(r, [
        ("T-90", "未起動時のcontinue", _t90),
        ("T-91", "未起動時のprint", _t91),
    ])
    run_scenario(r, [
        ("T-92", "存在しないシンボルへのbreak", _t92),
        ("T-93", "不正アドレスのx", _t93),
        ("T-94", "引数不足", _t94),
        ("T-95", "存在しない変数のprint", _t95),
        ("T-96", "存在しないfile:line", _t96),
    ])
    run_scenario(r, [("T-97", "二重run", _t97)])


def _t90(s):
    out = s.cmd("c")
    check_contains(out, "no process", "T-90")


def _t91(s):
    out = s.cmd("p x")
    check_contains(out, "no process", "T-91")


def _t92(s):
    s.cmd("run target")
    out = s.cmd("b no_such_function")
    check_regex(out, r"unknown symbol", "T-92")
    out = s.cmd("show bp")
    check_contains(out, "no breakpoints", "T-92 (not added)")


def _t93(s):
    out = s.cmd("x 0x1")
    check_regex(out, r"(ptrace peek|error|fail)", "T-93")
    out = s.cmd("help")
    check_contains(out, "Commands:", "T-93 (REPL continues)")


def _t94(s):
    out = s.cmd("b")
    check_regex(out, r"usage", "T-94")


def _t95(s):
    out = s.cmd("p no_such_var")
    check_contains(out, "unknown variable", "T-95")


def _t96(s):
    out = s.cmd("b nofile.c:9999")
    check_regex(out, r"no line info|error|not found", "T-96")
    out = s.cmd("show bp")
    check_contains(out, "no breakpoints", "T-96 (not added)")


def _t97(s):
    out = s.cmd("run target")
    check_contains(out, "process started", "T-97 setup")
    old_pid = out.split("pid=")[1].split()[0].strip()

    out = s.cmd("run target")
    # Designed behavior (see exec.c's run_target): re-running kills the
    # existing debuggee first, then starts a fresh one - no leaked
    # background process, no garbled interleaved stdout from both.
    check_contains(out, "process killed (pid=%s)" % old_pid, "T-97 (old process killed first)")
    check_contains(out, "process started", "T-97 (new process then started)")
    out = s.cmd("b add")
    check_contains(out, "breakpoint set", "T-97 (new session fully usable)")
    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-97")
