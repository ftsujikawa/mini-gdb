"""
04_テスト仕様書.md 8b章「マルチプロセス（fork）テスト」(T-85~T-89c)。

`fork_target.c`: 親プロセスが3子プロセスを`fork`し、各子が`worker`を
呼び出して自分だけのコピーオンライトの`shared_total`を変更する。8a章
と同様、実プロセス/実スレッドのタイミングは非決定的なため、固定回数の
`c`ではなく「期待する出力が現れるまで繰り返す」方式で検証する。

T-87a（親のCOW独立性）・T-88a（子1つ終了時のセッション継続）・T-89a
（ロック中は他プロセス停止）はいずれも「まだ全プロセスが終了していない
中間状態」を観測する必要があるため、`c`が返るのを待つのではなく
`Session.expect()`で該当メッセージの出現そのものを待つ（`c`は複数の
プロセス終了をまとめて1回で報告し切ってプロンプトに戻ることがあり、
プロンプト到達を待ってからでは中間状態を観測できないため）。
"""
import re

from harness import Session, check, check_contains, check_not_contains, check_regex, extract, run_scenario

STABILITY_REPEATS = 3


def run(r):
    run_scenario(r, [
        ("T-85", "子プロセス生成検知", _t85),
        ("T-85a", "プロセス一覧表示（Pid列）", _t85a),
        ("T-86", "複数子プロセスでのブレークポイント命中", _t86),
        ("T-86a", "fork後に設置したブレークポイントの伝播", _t86a),
    ])
    run_scenario(r, [
        ("T-87/87a-run", "watch設置、最初のヒットとCOW確認", _t87_87a_run),
        ("T-87", "ウォッチポイントの全プロセス伝播", _t87),
        ("T-87a", "コピーオンライトによるプロセス間メモリ独立性", _t87a),
        ("T-88/88b-run", "正常終了まで`c`を繰り返す", _t88_88b_run),
        ("T-88", "正常終了", _t88),
        ("T-88b", "SIGCHLDの自動転送", _t88b),
    ])
    run_scenario(r, [("T-88a", "子プロセス終了時のセッション継続", _t88a)])
    run_scenario(r, [("T-89", "強制終了時のクリーンアップ", _t89)])
    run_scenario(r, [("T-89a", "ロックの子プロセスへの適用", _t89a)])
    r.step("T-89b", "安定性（繰り返し実行）", _t89b)
    r.step("T-89c", "既存単一プロセス機能の非破壊確認", _t89c)


def _run_until(s, marker, max_iters=10, timeout=15):
    collected = []
    for _ in range(max_iters):
        out = s.cmd("c", timeout=timeout)
        collected.append(out)
        if marker in out or "process exited" in out or "no process" in out:
            break
    return "".join(collected)


def _thread_id_for_pid(threads_out, pid):
    for m in re.finditer(r"^\s*[*L ]*(\d+)\s+(\d+)\s+(\d+)\s", threads_out, re.MULTILINE):
        id_, row_pid, _tid = m.groups()
        if row_pid == pid:
            return id_
    return None


def _t85(s):
    out = s.cmd("run fork_target")
    s.parent_pid = extract(out, r"process started pid=(\d+)", label="T-85 setup")
    s.cmd("b worker")
    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-85")
    m = check_regex(out, r"\[\+\] pid=(\d+) tid=(\d+)", "T-85")
    pid, tid = m.group(1), m.group(2)
    check(pid == tid, "T-85: child process pid (%s) should equal its own tid (%s)" % (pid, tid))


def _t85a(s):
    out = s.cmd("threads")
    check_regex(out, r"Id\s+Pid\s+Tid\s+Location", "T-85a (header)")
    pids = set(re.findall(r"^\s*[*L ]*\d+\s+(\d+)\s+\d+\s", out, re.MULTILINE))
    check(len(pids) >= 2, "T-85a: expected at least 2 distinct Pid values (parent+child):\n%s" % out)
    check_regex(out, r"(\d+)\s+\1\s", "T-85a (child row has Pid == Tid)")


def _t86(s):
    out = _run_until(s, "breakpoint hit", max_iters=4)
    out += s.cmd("threads")
    pids = set(re.findall(r"^\s*[*L ]*\d+\s+(\d+)\s+\d+\s", out, re.MULTILINE))
    check(len(pids) >= 2, "T-86: expected multiple distinct processes tracked:\n%s" % out)


def _t86a(s):
    out = s.cmd("b fork_target.c:45")
    check_contains(out, "breakpoint set", "T-86a")
    hit = ""
    for _ in range(8):
        out = s.cmd("c", timeout=15)
        hit += out
        if "fork_target.c:45" in out:
            break
        if "process exited" in out or "no process" in out:
            break
    check_contains(hit, "fork_target.c:45", "T-86a (new bp hit by some process)")


def _t87_87a_run(s):
    out = s.cmd("run fork_target")
    s.parent_pid = extract(out, r"process started pid=(\d+)", label="T-87 setup")
    s.cmd("b worker")
    s.cmd("c")
    s.cmd("del 1")
    out = s.cmd("watch shared_total")
    check_contains(out, "Hardware watchpoint 1: shared_total", "T-87 setup")

    out = s.cmd("c", timeout=15)
    s.first_hit = out

    threads_out = s.cmd("threads")
    parent_id = _thread_id_for_pid(threads_out, s.parent_pid)
    check(parent_id is not None, "T-87a: could not find parent's Id in threads listing:\n%s" % threads_out)
    s.cmd("thread " + parent_id)
    s.parent_shared_total = s.cmd("p shared_total")


def _t87(s):
    check_contains(s.first_hit, "Hardware watchpoint 1: shared_total", "T-87")
    check_regex(s.first_hit, r"Old value = \d+", "T-87")
    check_regex(s.first_hit, r"New value = \d+", "T-87")


def _t87a(s):
    check_contains(s.parent_shared_total, "shared_total = 0", "T-87a (parent's own COW copy stays 0)")


def _t88_88b_run(s):
    s.collected = s.first_hit + _run_until(s, "all children done", max_iters=12)


def _t88(s):
    check_contains(s.collected, "all children done", "T-88")
    check_contains(s.collected, "parent's own shared_total=0", "T-88")
    check_contains(s.collected, "process exited", "T-88")
    check_not_contains(s.collected, "signal=11", "T-88 (no crash)")


def _t88b(s):
    check_not_contains(s.collected, "stopped signal=17", "T-88b (SIGCHLD must not surface as a stop)")


def _t88a(s):
    s.cmd("run fork_target")
    s.cmd("b worker")
    s.cmd("c")
    s.cmd("del 1")
    # Watch for the intermediate message directly, rather than waiting
    # for the next prompt: a single `c` can silently run every process
    # to completion in one go once no breakpoint is left, so by the
    # time the prompt reappears the whole debuggee may already be gone
    # - this would make the "session keeps tracking others" assertion
    # untestable if we waited for cmd()'s prompt-bounded return.
    s.send("c")
    out = s.expect(r"other tracked processes remain", timeout=15)
    check_contains(out, "process pid=", "T-88a")
    # Drain the rest so we return to a clean prompt before further use.
    s.expect(r"\(tdb\) ", timeout=15)


def _t89(s):
    s.cmd("run fork_target")
    s.cmd("b worker")
    s.cmd("c")
    s.cmd("c")
    out = s.cmd("kill")
    check_contains(out, "process killed", "T-89")
    out = s.cmd("threads")
    check_contains(out, "no threads", "T-89")


def _t89a(s):
    s.cmd("run fork_target")
    s.cmd("b worker")
    out = s.cmd("c")
    child_tid = extract(out, r"\[\+\] pid=\d+ tid=(\d+)", label="T-89a")

    out = s.cmd("threads")
    others_rip = {}
    for m in re.finditer(r"^\s*[*L ]*\d+\s+(\d+)\s+(\d+)\s+(0x[0-9a-f]+)", out, re.MULTILINE):
        _pid, tid, rip = m.groups()
        if tid != child_tid:
            others_rip[tid] = rip

    out = s.cmd("lock " + child_tid)
    check_contains(out, "locked to tid=" + child_tid, "T-89a")

    # Pause the locked child at a 2nd breakpoint (still inside worker,
    # not yet exited) before letting it run, so we can observe "other
    # processes stay frozen" *while still locked* - checking only
    # after the lock naturally auto-clears (on the child exiting)
    # would be too late, since auto-clear itself resumes everyone.
    s.cmd("b fork_target.c:45")
    out = s.cmd("c", timeout=15)
    check_contains(out, "breakpoint hit", "T-89a (locked child reaches 2nd bp, not exited)")

    out = s.cmd("threads")
    for tid, rip in others_rip.items():
        check_contains(out, rip, "T-89a (other tid=%s rip unchanged while locked)" % tid)

    s.cmd("del 2")
    out = _run_until(s, "scheduler lock cleared", max_iters=6)
    check_contains(out, "scheduler lock cleared", "T-89a (auto-unlock once locked child exits)")


def _t89b():
    for i in range(STABILITY_REPEATS):
        s = Session()
        try:
            s.cmd("run fork_target")
            s.cmd("b worker")
            s.cmd("c")
            s.cmd("del 1")
            out = _run_until(s, "all children done", max_iters=12)
            check_contains(out, "process exited", "T-89b (iteration %d)" % i)
            check_not_contains(out, "signal=11", "T-89b (iteration %d, no crash)" % i)
        finally:
            s.close()


def _t89c():
    s = Session()
    try:
        s.cmd("run target")
        s.cmd("b add")
        out = s.cmd("c")
        check_contains(out, "breakpoint hit", "T-89c")
        out = s.cmd("threads")
        pids = set(re.findall(r"^\s*[*L ]*\d+\s+(\d+)\s+\d+\s", out, re.MULTILINE))
        check(len(pids) == 1, "T-89c: single-process debuggee should show one Pid value:\n%s" % out)
    finally:
        s.close()
