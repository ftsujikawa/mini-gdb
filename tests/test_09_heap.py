"""
04_テスト仕様書.md 9章「ヒープトレース／リーク検出テスト」(T-70~T-77、
本節独自のナンバリング。8a章のT-70~T-77とは無関係な別の番号割当て)。
"""
from harness import check, check_contains, check_not_contains, check_regex, run_scenario


def run(r):
    run_scenario(r, [
        ("T-70", "トレース有効化", _t70),
        ("T-71", "リーク検出シナリオ", _t71),
    ])
    run_scenario(r, [
        ("T-72", "生存確保一覧", _t72),
        ("T-73", "解放反映確認", _t73),
        ("T-74", "呼び出し元表示", _t74),
        ("T-75", "プロセス終了時サマリ", _t75),
        ("T-77", "透過的継続確認", _t77),
    ])
    run_scenario(r, [("T-76", "トレース無効時の非計測", _t76)])


def _t70(s):
    out = s.cmd("set heap-trace on")
    check_not_contains(out, "error", "T-70")
    check_not_contains(out, "unknown", "T-70")


def _t71(s):
    s.cmd("run leak_target")
    s.cmd("c", timeout=5)
    out = s.cmd("show leaks")
    check_regex(out, r"200 bytes", "T-71 (200-byte malloc leak)")
    check_regex(out, r"160 bytes", "T-71 (160-byte calloc leak)")
    check_contains(out, "2 leak(s)", "T-71")


def _t72(s):
    s.cmd("set heap-trace on")
    s.cmd("run leak_target")
    s.cmd("b leak_target.c:31")
    out = s.cmd("c")
    check_contains(out, "leak_target.c:31", "T-72 setup (stopped before free(ok))")
    out = s.cmd("show heap")
    check_contains(out, "100 bytes", "T-72 (ok's 100-byte malloc still live)")
    check_contains(out, "3 live allocation(s)", "T-72")


def _t73(s):
    out = s.cmd("c", timeout=5)
    check_contains(out, "process exited", "T-73 setup (ran to completion)")
    out = s.cmd("show leaks")
    check_not_contains(out, "100 bytes", "T-73 (freed 100-byte alloc must not appear)")
    check_contains(out, "200 bytes", "T-73 (still-leaked allocations remain listed)")


def _t74(s):
    out = s.cmd("show leaks")
    check_regex(out, r"at .*leak_target\.c:\d+", "T-74 (caller file:line shown)")


def _t75(s):
    # The exit-time summary was already printed during T-73's `c`;
    # re-derive it from a fresh run to check it directly here.
    s.cmd("run leak_target")
    out = s.cmd("c", timeout=5)
    check_regex(out, r"\[heap\] \d+ leak\(s\) at process exit", "T-75")


def _t77(s):
    # T-71/T-72/T-73 already ran clean through several malloc/calloc
    # calls without ever stopping at them (only user breakpoints did);
    # confirm no "breakpoint hit"-style stop was ever attributed to a
    # heap hook address by checking the transcript doesn't contain any
    # unexpected extra stop between run and the free(ok) breakpoint.
    s.cmd("run leak_target")
    out = s.cmd("c", timeout=5)
    check_not_contains(out, "malloc", "T-77 (heap hooks must not surface as a visible stop)")


def _t76(s):
    s.cmd("set heap-trace off")
    s.cmd("run leak_target")
    out = s.cmd("c", timeout=5)
    check_not_contains(out, "leak(s) at process exit", "T-76 (no summary without tracing)")
    out = s.cmd("show leaks")
    check(
        "200 bytes" not in out,
        "T-76: no leaks should be tracked with heap-trace off:\n%s" % out,
    )
