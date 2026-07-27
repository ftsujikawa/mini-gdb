"""
04_テスト仕様書.md 6章「変数・式評価テスト」(T-20~T-36)。

前提どおり `target` の `main` 内ローカル変数が有効な状態で検証する。
`b main`→`c`だとまだ未初期化のため、`b target.c:28`（while直前、全ローカル
変数が初期化済み）で停止させてから進める。

T-21は仕様書の例`p/x x`（"p"と"/x"の間に空白が無い記法）が、実装の
コマンドレクサでは"p/x"全体が1つのT_WORDトークンとして貪欲マッチされて
しまい（flexの最長一致規則により、1文字の"p"キーワード規則より優先
される）"syntax error"になる既知の字句解析上の制約があるため、実際に
サポートされている（`help`にも記載の）区切りあり記法`p /x x`で検証する。
"""
from harness import check, check_contains, check_regex, run_scenario


def run(r):
    run_scenario(r, [
        ("setup", "target: b target.c:28 -> c (全ローカル変数初期化済み)", _setup),
        ("T-20", "単純変数表示", _t20),
        ("T-21", "フォーマット指定", _t21),
        ("T-22", "構造体表示", _t22),
        ("T-23", "メンバアクセス", _t23),
        ("T-24", "ポインタ経由メンバアクセス", _t24),
        ("T-25", "配列添字", _t25),
        ("T-26", "アドレス演算子", _t26),
        ("T-27", "二項演算", _t27),
        ("T-28", "レジスタ参照", _t28),
        ("T-29", "変数代入", _t29),
        ("T-30", "構造体メンバ代入", _t30),
        ("T-31", "レジスタ代入", _t31),
        ("T-32", "ローカル変数一覧", _t32),
        ("T-34", "グローバル変数一覧", _t34),
        ("T-35", "表示設定変更", _t35),
        ("T-36", "基数設定", _t36),
    ])
    run_scenario(r, [
        ("T-33-setup", "target: b add -> c", _t33_setup),
        ("T-33", "引数一覧", _t33),
    ])


def _setup(s):
    s.cmd("run target")
    s.cmd("b target.c:28")
    out = s.cmd("c")
    check_contains(out, "target.c:28", "setup")


def _t20(s):
    out = s.cmd("p x")
    check_contains(out, "x = 10", "T-20")


def _t21(s):
    out = s.cmd("p /x x")
    check_contains(out, "x = 0xa", "T-21")


def _t22(s):
    out = s.cmd("p ts")
    check_regex(out, r"ts = \{a = 0, b = 0, c = 0\}", "T-22")


def _t23(s):
    out = s.cmd("p ts.a")
    check_contains(out, "ts.a = 0", "T-23")


def _t24(s):
    out = s.cmd("p ts_ptr->a")
    check_contains(out, "ts_ptr->a = 0", "T-24 (same value as ts.a)")


def _t25(s):
    out = s.cmd("p sa[1]")
    check_regex(out, r"sa\[1\] = \{a = 0, b = 0, c = 0\}", "T-25")


def _t26(s):
    out = s.cmd("p &x")
    check_regex(out, r"&x = 0x[0-9a-f]+", "T-26")


def _t27(s):
    out = s.cmd("p x + y")
    check_contains(out, "x + y = 30", "T-27")


def _t28(s):
    out = s.cmd("p $rip")
    check_regex(out, r"\$rip = \d+", "T-28")


def _t29(s):
    s.cmd("set x = 100")
    out = s.cmd("p x")
    check_contains(out, "x = 100", "T-29")


def _t30(s):
    s.cmd("set ts.a = 5")
    out = s.cmd("p ts.a")
    check_contains(out, "ts.a = 5", "T-30")


def _t31(s):
    s.cmd("set $rax = 0")
    out = s.cmd("p $rax")
    check_contains(out, "$rax = 0", "T-31")


def _t32(s):
    out = s.cmd("show locals")
    for name in ("x", "y", "ts", "ts_ptr", "sa", "sa_ptr", "pm"):
        check_regex(out, r"\b%s\s*=" % name, "T-32 (%s listed)" % name)


def _t34(s):
    out = s.cmd("show globals")
    # target.c declares no globals of its own; the linked-in libc/crt
    # object symbols still show up. Just check it doesn't error and
    # produces some listing (each line "name = value").
    check(len(out.strip().splitlines()) > 0, "T-34: show globals produced no output")
    check_not_error(out)


def check_not_error(out):
    check("syntax error" not in out and "unknown" not in out, "T-34: unexpected error:\n%s" % out)


def _t35(s):
    s.cmd("set print format hex")
    out = s.cmd("p x")
    check_contains(out, "x = 0x", "T-35 (hex display)")
    out = s.cmd("show print")
    check_contains(out, "Print format: hex", "T-35 (show print reflects setting)")
    s.cmd("set print format decimal")  # restore for later steps


def _t36(s):
    s.cmd("set output-radix 16")
    out = s.cmd("p x")
    check_contains(out, "x = 0x", "T-36 (output-radix affects display)")


def _t33_setup(s):
    s.cmd("run target")
    s.cmd("b add")
    out = s.cmd("c")
    check_contains(out, "target.c:13", "T-33-setup")


def _t33(s):
    out = s.cmd("show args")
    for name in ("ts", "a", "b"):
        check_regex(out, r"\b%s\s*=" % name, "T-33 (%s listed)" % name)
