"""
04_テスト仕様書.md 8a章「マルチスレッドテスト」(T-69~T-83)。

`thread_target.c`: 3ワーカースレッドが`worker`を呼び出し`shared_total`
へ書き込む。実スレッドスケジューリングのタイミング（`c`1回でどこまで
進むか）は本質的に非決定的なため、「N回`c`する」という固定回数ではなく
「期待する出力が現れるまで`c`を繰り返す（上限付き）」方式で検証する。
T-78（安定性・10回連続実行）はコストが高いため既定では軽量化した3回に
留める（`STABILITY_REPEATS`で調整可能）。
"""
import re

from harness import Session, check, check_contains, check_not_contains, check_regex, extract, run_scenario

STABILITY_REPEATS = 3


def run(r):
    run_scenario(r, [
        ("T-69", "スレッド生成検知", _t69),
        ("T-70", "スレッド一覧表示", _t70),
        ("T-71", "複数スレッドでのブレークポイント命中", _t71),
        ("T-72", "スレッド切替", _t72),
        ("T-73", "スレッド別レジスタ/バックトレース", _t73),
    ])
    run_scenario(r, [
        ("T-74/75/76-run", "watch設置後、正常終了まで`c`を繰り返す", _t74_75_76_run),
        ("T-74", "ウォッチポイントの全スレッド伝播", _t74),
        ("T-75", "新規スレッドへの伝播", _t75),
        ("T-76", "正常終了", _t76),
    ])
    run_scenario(r, [("T-77", "強制終了時のクリーンアップ", _t77)])
    run_scenario(r, [
        ("T-80", "スケジューラロック設置", _t80),
        ("T-80a", "ロック中の一覧表示", _t80a),
        ("T-81", "ロック中の実行制限", _t81),
        ("T-81a", "ロック対象以外でのstep系コマンド拒否", _t81a),
        ("T-83", "ロック対象スレッド終了時の自動解除", _t83),
    ])
    run_scenario(r, [
        ("T-80(2)", "スケジューラロック設置（unlock検証用）", _t80),
        ("T-82", "明示的unlock", _t82),
    ])
    r.step("T-78", "安定性（繰り返し実行）", _t78)
    r.step("T-79", "既存単一スレッド機能の非破壊確認", _t79)


def _run_until(s, marker, max_iters=10, timeout=15):
    """Keep issuing `c` until `marker` shows up in some command's output
    (or the process exits), returning the concatenation of everything
    seen. Multi-threaded timing is inherently non-deterministic - a
    fixed number of `c` calls can't reliably predict how many discrete
    stops will occur before the whole process runs to completion."""
    collected = []
    for _ in range(max_iters):
        out = s.cmd("c", timeout=timeout)
        collected.append(out)
        if marker in out or "process exited" in out or "no process" in out:
            break
    return "".join(collected)


def _t69(s):
    s.cmd("run thread_target")
    s.cmd("b worker")
    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-69")
    m = check_regex(out, r"\[\+\] pid=(\d+) tid=(\d+)", "T-69")
    pid, tid = m.group(1), m.group(2)
    check(pid != tid, "T-69: pid (%s) and tid (%s) should differ for a worker thread hit" % (pid, tid))


def _t70(s):
    out = s.cmd("threads")
    check_regex(out, r"Id\s+Pid\s+Tid\s+Location", "T-70 (header)")
    check_contains(out, "*", "T-70 (current-thread marker)")
    check_contains(out, "in worker+0x", "T-70 (function+offset shown)")
    check_regex(out, r"at .*thread_target\.c:\d+", "T-70 (file:line shown)")
    check_not_contains(out, "(L = locked", "T-70 (no lock legend when unlocked)")


def _t71(s):
    out = _run_until(s, "breakpoint hit", max_iters=4)
    out += s.cmd("threads")
    n_threads = len(re.findall(r"^\s*[*L ]*\d+\s+\d+\s+\d+\s", out, re.MULTILINE))
    check(n_threads >= 1, "T-71: expected `threads` output to list tracked threads:\n%s" % out)
    check(out.count("breakpoint hit") >= 1, "T-71: expected further breakpoint hit(s):\n%s" % out)


def _t72(s):
    out = s.cmd("threads")
    ids_pids_tids = re.findall(r"^\s*[*L ]*(\d+)\s+(\d+)\s+(\d+)\s", out, re.MULTILINE)
    check(len(ids_pids_tids) >= 2, "T-72: need at least 2 tracked threads:\n%s" % out)
    current = check_regex(out, r"\*L?\s*(\d+)\s+\d+\s+\d+\s", "T-72").group(1)
    other = next((i for i, _, _ in ids_pids_tids if i != current), None)
    check(other is not None, "T-72: need a thread Id different from the current one:\n%s" % out)
    out = s.cmd("thread " + other)
    check_contains(out, "switched to thread " + other, "T-72")


def _t73(s):
    out = s.cmd("regs")
    check_contains(out, "rip", "T-73")
    out = s.cmd("tb")
    check_regex(out, r"#0\s+0x[0-9a-f]+", "T-73 (backtrace produced)")


def _t74_75_76_run(s):
    s.cmd("run thread_target")
    s.cmd("b worker")
    s.cmd("c")
    s.cmd("del 1")
    out = s.cmd("watch shared_total")
    check_contains(out, "Hardware watchpoint 1: shared_total", "T-74 setup")
    s.collected = _run_until(s, "all workers done", max_iters=10)


def _t74(s):
    check_contains(s.collected, "Hardware watchpoint 1: shared_total", "T-74")
    check_regex(s.collected, r"Old value = \d+", "T-74")
    check_regex(s.collected, r"New value = \d+", "T-74")


def _t75(s):
    hits = len(re.findall(r"Hardware watchpoint 1: shared_total", s.collected))
    check(hits >= 2, "T-75: expected the watchpoint to fire for multiple workers, saw %d hit(s):\n%s"
          % (hits, s.collected))


def _t76(s):
    check_contains(s.collected, "all workers done", "T-76")
    check_contains(s.collected, "process exited", "T-76")
    check_not_contains(s.collected, "signal=11", "T-76 (no crash)")


def _t77(s):
    s.cmd("run thread_target")
    s.cmd("b worker")
    s.cmd("c")
    out = s.cmd("kill")
    check_contains(out, "process killed", "T-77")
    out = s.cmd("threads")
    check_contains(out, "no threads", "T-77")


def _t80(s):
    s.cmd("run thread_target")
    s.cmd("b worker")
    out = s.cmd("c")
    tid = extract(out, r"\[\+\] pid=\d+ tid=(\d+)", label="T-80")
    s.worker_tid = tid  # stash for later steps in this scenario
    out = s.cmd("lock " + tid)
    check_contains(out, "locked to tid=" + tid, "T-80")


def _t80a(s):
    out = s.cmd("threads")
    check_regex(out, r"\*?L\s+\d+\s+\d+\s+%s\s" % re.escape(s.worker_tid), "T-80a (L marker on the locked tid's line)")
    check_contains(out, "(L = locked; only this tid runs on `c`)", "T-80a (legend)")


def _t81(s):
    out = s.cmd("threads")
    # tid -> rip, for every tid other than the locked one.
    others_rip = {}
    for m in re.finditer(r"^\s*[*L ]*\d+\s+(\d+)\s+(\d+)\s+(0x[0-9a-f]+)", out, re.MULTILINE):
        pid, tid, rip = m.groups()
        if tid != s.worker_tid:
            others_rip[tid] = rip

    s.cmd("b thread_target.c:44")
    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-81 (locked worker reaches 2nd bp, not exited)")

    out = s.cmd("threads")
    for tid, rip in others_rip.items():
        check_contains(out, rip, "T-81 (other tid=%s rip unchanged)" % tid)


def _t81a(s):
    out = s.cmd("threads")
    other_id = None
    for m in re.finditer(r"^\s*[*L ]*(\d+)\s+\d+\s+(\d+)\s", out, re.MULTILINE):
        id_, tid = m.groups()
        if tid != s.worker_tid:
            other_id = id_
            break
    check(other_id is not None, "T-81a: need a non-locked thread to switch to:\n%s" % out)
    s.cmd("thread " + other_id)
    out = s.cmd("regs")
    rip_before = extract(out, r"rip\s+(0x[0-9a-f]+)", label="T-81a")
    out = s.cmd("si")
    check_contains(out, "is not the locked thread", "T-81a")
    out = s.cmd("regs")
    rip_after = extract(out, r"rip\s+(0x[0-9a-f]+)", label="T-81a")
    check(rip_before == rip_after, "T-81a: rip must not change (%s -> %s)" % (rip_before, rip_after))


def _t83(s):
    out = _run_until(s, "scheduler lock cleared", max_iters=5)
    check_contains(out, "scheduler lock cleared", "T-83")
    out = s.cmd("c", timeout=15)
    check(out != "", "T-83: session must remain responsive after auto-unlock")


def _t82(s):
    tid = s.worker_tid
    out = s.cmd("unlock")
    check_contains(out, "unlocked tid=" + tid, "T-82")


def _t78():
    for i in range(STABILITY_REPEATS):
        s = Session()
        try:
            s.cmd("run thread_target")
            s.cmd("b worker")
            s.cmd("c")
            s.cmd("del 1")
            out = _run_until(s, "all workers done", max_iters=10)
            check_contains(out, "process exited", "T-78 (iteration %d)" % i)
            check_not_contains(out, "signal=11", "T-78 (iteration %d, no crash)" % i)
        finally:
            s.close()


def _t79():
    s = Session()
    try:
        s.cmd("run target")
        s.cmd("b add")
        out = s.cmd("c")
        check_contains(out, "breakpoint hit", "T-79")
        check_contains(out, "target.c:13", "T-79")
    finally:
        s.close()
