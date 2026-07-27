"""
04_テスト仕様書.md 4章「プロセス起動・実行制御テスト」(T-01~T-09)。

`target` は PIE でビルドされる（gcc既定）ため、T-01~T-03 の中で
そのまま T-02（PIEロードベース取得）も検証する。`target.c` 自体が
`while(1) { ...; sleep(1); }` の無限ループプログラムなので、
T-08a（kill）・T-09（SIGINT転送）用の「無限ループプログラム」として
そのまま使う。T-08（正常終了）は `leak_target` を使う。

各シナリオは基本的に独立したフレッシュな `Session` を使うため、
あるシナリオの失敗が他のシナリオの実行を妨げることはない（`run()`側で
1シナリオ＝1 try/exceptとし、他は影響を受けない）。T-08a~T-08dのみ、
同一セッション内の連続手順のため一括で1シナリオとして扱う。
"""
import time

from harness import check, check_contains, check_not_contains, check_regex, extract, run_scenario


def run(r):
    run_scenario(r, [
        ("T-01", "通常起動", _t01),
        ("T-02/T-03", "PIEロードベース取得・continue", _t02_t03),
        ("T-04", "命令ステップ(si)", _t04),
        ("T-07", "関数リターンまで実行(up)", _t07),
    ])
    run_scenario(r, [("T-06", "ステップオーバー(n)", _t06)])
    run_scenario(r, [("T-05", "ソース行ステップ(s)", _t05)])
    run_scenario(r, [("T-06b", "ステップオーバー中のブレークポイント命中", _t06b)])
    run_scenario(r, [("T-06a", "ステップオーバー時の分岐スキップ", _t06a)])
    run_scenario(r, [("T-08", "プロセス正常終了", _t08)])
    run_scenario(r, [
        ("T-08a", "強制終了(kill)", _t08a),
        ("T-08b", "強制終了後の状態", _t08b),
        ("T-08c", "未起動時のkill", _t08c),
        ("T-08d", "kill後の再起動", _t08d),
    ])
    run_scenario(r, [("T-09", "SIGINT転送（Ctrl+C）", _t09)])


def _t01(s):
    out = s.cmd("run target")
    check_regex(out, r"\[\+\] process started pid=\d+", "T-01")


def _t02_t03(s):
    out = s.cmd("b add")
    bp_addr = int(extract(out, r"breakpoint set at (0x[0-9a-f]+)", label="T-02"), 16)
    # PIE: a real load-base-relocated address should be well above a
    # typical non-PIE link address (0x400000ish) - use a generous
    # threshold that only a relocated/mmap-region address can clear.
    check(bp_addr > 0x100000000, "T-02: breakpoint address 0x%x does not look PIE-relocated" % bp_addr)

    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-03")
    check_contains(out, "target.c:13", "T-03 (stopped inside add, prologue passed)")

    out = s.cmd("regs")
    rip = int(extract(out, r"rip\s+(0x[0-9a-f]+)", label="T-02 regs"), 16)
    check(abs(rip - bp_addr) < 0x1000, "T-02: regs rip 0x%x far from breakpoint addr 0x%x" % (rip, bp_addr))


def _t04(s):
    out = s.cmd("regs")
    prev_rip = extract(out, r"rip\s+(0x[0-9a-f]+)", label="T-04")
    for i in range(3):
        out = s.cmd("si")
        check_contains(out, "stepped", "T-04 (si #%d)" % i)
        out = s.cmd("regs")
        rip = extract(out, r"rip\s+(0x[0-9a-f]+)", label="T-04")
        check(rip != prev_rip, "T-04: rip did not change across si (%s -> %s)" % (prev_rip, rip))
        prev_rip = rip


def _t07(s):
    out = s.cmd("up")
    check_contains(out, "returned to", "T-07")
    check_contains(out, "target.c", "T-07 (back in caller)")


def _t06(s):
    s.cmd("run target")
    s.cmd("b target.c:30")
    s.cmd("c")
    out = s.cmd("n")
    check_contains(out, "target.c:32", "T-06 (stepped over add, landed on next line)")
    check_not_contains(out, "target.c:13", "T-06 (must not enter add)")


def _t05(s):
    s.cmd("run target")
    s.cmd("b target.c:30")
    s.cmd("c")
    out = s.cmd("s")
    # `add`'s first line-table entry is its opening brace (line 12,
    # prologue) rather than line 13 - either is "stepped into add".
    check(
        "target.c:12" in out or "target.c:13" in out,
        "T-05 (stepped into add): expected target.c:12 or :13 in output:\n%s" % out,
    )


def _t06b(s):
    s.cmd("run target")
    s.cmd("b main")
    s.cmd("c")
    # Step forward (n) until reaching the add-call line.
    reached = False
    for _ in range(15):
        out = s.cmd("n")
        if "target.c:30" in out:
            reached = True
            break
    check(reached, "T-06b: never reached target.c:30 via n")
    s.cmd("b add")
    out = s.cmd("n")
    check_contains(out, "breakpoint hit", "T-06b (bp inside add must fire, not be skipped)")
    check_contains(out, "target.c:13", "T-06b")


def _t06a(s):
    s.cmd("run leak_target")
    s.cmd("b main")
    s.cmd("c")
    reached = False
    for _ in range(15):
        out = s.cmd("n")
        if "leak_target.c:26" in out:
            reached = True
            break
    check(reached, "T-06a: never reached leak_target.c:26 (the if-condition line) via n")
    out = s.cmd("n")
    check_not_contains(out, "leak_target.c:27", "T-06a (must not enter the false if-branch)")
    check_contains(out, "leak_target.c:31", "T-06a (must land on the line actually executed next)")
    check_not_contains(out, "process exited", "T-06a (must not have run off the end)")


def _t08(s):
    s.cmd("run leak_target")
    out = s.cmd("c", timeout=5)
    check_contains(out, "process exited", "T-08")
    out = s.cmd("regs")
    check_contains(out, "no process", "T-08 (process-dependent command after exit)")


def _t08a(s):
    s.cmd("run target")
    s.cmd("b add")
    s.cmd("c")
    out = s.cmd("kill")
    check_contains(out, "process killed", "T-08a")


def _t08b(s):
    out = s.cmd("regs")
    check_contains(out, "no process", "T-08b")


def _t08c(s):
    out = s.cmd("kill")
    check_contains(out, "no process", "T-08c")


def _t08d(s):
    out = s.cmd("run target")
    check_regex(out, r"\[\+\] process started pid=\d+", "T-08d")
    out = s.cmd("b add")
    check_contains(out, "breakpoint set", "T-08d (b works after restart)")
    out = s.cmd("c")
    check_contains(out, "breakpoint hit", "T-08d (c works after restart)")


def _t09(s):
    s.cmd("run target")
    s.send("c")
    time.sleep(0.5)
    s.interrupt()
    out = s.expect(r"\(tdb\) ", timeout=5)
    check_contains(out, "stopped signal=2", "T-09 (SIGINT forwarded and reported)")
    out = s.cmd("b add")
    check_contains(out, "breakpoint set", "T-09 (REPL still operable after SIGINT stop)")
