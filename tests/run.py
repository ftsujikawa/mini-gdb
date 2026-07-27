#!/usr/bin/env python3
"""
Runs the tdb automated test suite (tests/test_*.py), each module mapping
to one section of docs/04_テスト仕様書.md, and prints a PASS/FAIL/ERROR/SKIP
summary per spec test ID. Exits nonzero if anything failed.

Usage:
    python3 tests/run.py                 # run every section
    python3 tests/run.py 08a 08b          # run only tests/test_08a_*.py, test_08b_*.py
"""
import importlib
import os
import sys
import time

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)

from harness import Reporter  # noqa: E402

SECTIONS = [
    ("04", "test_04_process", "4. プロセス起動・実行制御"),
    ("05", "test_05_breakpoint", "5. ブレークポイント"),
    ("05a", "test_05a_watchpoint", "5a. ウォッチポイント"),
    ("06", "test_06_expr", "6. 変数・式評価"),
    ("07", "test_07_debuginfo", "7. デバッグ情報・ソース表示"),
    ("08", "test_08_state", "8. 実行状態参照"),
    ("08a", "test_08a_thread", "8a. マルチスレッド"),
    ("08b", "test_08b_fork", "8b. マルチプロセス（fork）"),
    ("09", "test_09_heap", "9. ヒープトレース／リーク検出"),
    ("10", "test_10_repl", "10. REPL・コマンドライン"),
    ("11", "test_11_errors", "11. 異常系"),
    ("12", "test_12_limits", "12. 非機能（制限値）"),
]


def main():
    requested = set(sys.argv[1:])
    sections = [s for s in SECTIONS if not requested or s[0] in requested]

    all_results = []  # (section_title, list of (id, status, msg))
    t0 = time.time()

    for key, modname, title in sections:
        path = os.path.join(TESTS_DIR, modname + ".py")
        if not os.path.exists(path):
            print("== %-45s [NOT IMPLEMENTED, skipping] ==" % title)
            continue

        print("== %-45s ==" % title)
        mod = importlib.import_module(modname)
        r = Reporter(title)
        try:
            mod.run(r)
        except Exception as e:
            print("  !! section crashed outside of a tracked step: %r" % e)
        for tid, status, msg in r.results:
            mark = {"PASS": "ok", "FAIL": "FAIL", "ERROR": "ERROR", "SKIP": "skip"}[status]
            print("  [%-5s] %-8s %s" % (mark, tid, msg))
        all_results.append((title, r.results))
        print()

    elapsed = time.time() - t0
    total = sum(len(res) for _, res in all_results)
    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}
    for _, res in all_results:
        for _, status, _ in res:
            counts[status] += 1

    print("=" * 60)
    print("TOTAL: %d tests in %.1fs -> PASS=%d FAIL=%d ERROR=%d SKIP=%d" %
          (total, elapsed, counts["PASS"], counts["FAIL"], counts["ERROR"], counts["SKIP"]))

    if counts["FAIL"] or counts["ERROR"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
