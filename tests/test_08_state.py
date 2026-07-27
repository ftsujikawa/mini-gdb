"""
04_テスト仕様書.md 8章「実行状態参照テスト」(T-60~T-68)。
"""
import re

from harness import check_contains, check_regex, extract, run_scenario


def run(r):
    run_scenario(r, [
        ("setup", "target: b add -> c", _setup),
        ("T-60", "レジスタ表示", _t60),
        ("T-61", "バックトレース", _t61),
        ("T-62", "シンボル一覧", _t62),
        ("T-64", "浮動小数点レジスタ表示", _t64),
        ("T-65", "SSEレジスタ代入（浮動小数点）", _t65),
        ("T-66", "x87レジスタ代入（浮動小数点）", _t66),
        ("T-67", "SSEレジスタ代入（ビットパターン）", _t67),
        ("T-68", "未知レジスタへの代入", _t68),
    ])
    run_scenario(r, [("T-63", "メモリ参照", _t63)])


def _setup(s):
    s.cmd("run target")
    s.cmd("b add")
    out = s.cmd("c")
    check_contains(out, "target.c:13", "setup")


def _t60(s):
    out = s.cmd("regs")
    for reg in ("rax", "rbx", "rip", "eflags", "cs", "ss"):
        check_regex(out, r"\b%s\b" % reg, "T-60 (%s shown)" % reg)
    check_contains(out, "target.c:13", "T-60 (current stop line shown)")


def _t61(s):
    out = s.cmd("tb")
    check_regex(out, r"#0\s+0x[0-9a-f]+ in add", "T-61 (frame 0 = add)")
    check_regex(out, r"#1\s+0x[0-9a-f]+ in main", "T-61 (frame 1 = main)")


def _t62(s):
    out = s.cmd("syms")
    check_regex(out, r"Num\s+Address\s+Size\s+Type\s+Name", "T-62 (header)")
    check_regex(out, r"func\s+add", "T-62 (add listed as func)")
    check_regex(out, r"func\s+main", "T-62 (main listed as func)")


def _t63(s):
    s.cmd("run target")
    s.cmd("b target.c:28")
    s.cmd("c")
    out = s.cmd("p &x")
    addr = extract(out, r"(0x[0-9a-f]+)", label="T-63")
    out = s.cmd("x " + addr)
    check_regex(out, re.escape(addr) + r"\s*:\s*0x[0-9a-f]+", "T-63")


def _t64(s):
    out = s.cmd("regs")
    for reg in ("fctrl", "fstat", "ftag", "fop", "fioff", "fooff", "mxcsr", "mxcsr_mask"):
        check_regex(out, r"\b%s\b" % reg, "T-64 (%s shown)" % reg)
    for i in range(8):
        check_regex(out, r"\bst%d\b" % i, "T-64 (st%d shown)" % i)
    for i in range(16):
        check_regex(out, r"\bxmm%d\b" % i, "T-64 (xmm%d shown)" % i)
    check_contains(out, "v2_double", "T-64 (xmm shows v2_double form)")


def _t65(s):
    s.cmd("set $xmm0 = 3.4")
    out = s.cmd("regs")
    check_regex(out, r"xmm0\s+\S+\s+\{v2_double = \{3\.4, 0\}\}", "T-65")


def _t66(s):
    s.cmd("set $st1 = 1.5")
    out = s.cmd("regs")
    check_regex(out, r"st1\s+\S+\s+1\.5", "T-66")


def _t67(s):
    s.cmd("set $xmm0 = 0x3ff0000000000000")
    out = s.cmd("regs")
    check_contains(out, "0x00000000000000003ff0000000000000", "T-67 (low 64 bits match)")
    check_contains(out, "{v2_double = {1, 0}}", "T-67")


def _t68(s):
    out = s.cmd("set $foo = 1")
    check_contains(out, "unknown register: $foo", "T-68")
    out = s.cmd("regs")
    check_contains(out, "rax", "T-68 (REPL still responsive)")
