"""
Test harness for tdb, driven interactively over a real pseudo-terminal
(so tdb's stdio is line-buffered exactly like a real terminal session,
without needing external tools like `stdbuf`). Standard library only -
no third-party dependencies, matching the project's own zero-dependency
policy for the debugger itself.

Each test module under tests/ implements one section of
docs/04_テスト仕様書.md as a sequential scenario (mirroring the spec's
own "T-69の後..." style step chaining) driven against a single Session,
reporting PASS/FAIL/ERROR per test ID via a Reporter.
"""
import os
import pty
import re
import select
import signal
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TDB = os.path.join(ROOT, "tdb")
PROMPT = r"\(tdb\) "
DEFAULT_TIMEOUT = 8.0


class TdbTimeout(AssertionError):
    pass


class Session:
    """One running `tdb` process attached to a pty, with expect()/cmd()
    helpers. Not thread-safe; one Session per test scenario."""

    def __init__(self, cwd=ROOT, timeout=DEFAULT_TIMEOUT, binary=TDB):
        self.timeout = timeout
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen(
            [binary],
            cwd=cwd,
            stdin=slave,
            stdout=slave,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        os.close(slave)
        self.buf = ""
        self.transcript = []
        self.expect(PROMPT)

    def _drain(self, deadline):
        remaining = deadline - time.time()
        if remaining <= 0:
            return False
        try:
            r, _, _ = select.select([self.master], [], [], remaining)
        except OSError:
            return False
        if not r:
            return False
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return False
        if not chunk:
            return False
        self.buf += chunk.decode(errors="replace")
        return True

    def expect(self, pattern, timeout=None):
        """Block until `pattern` (regex) appears in the buffered output,
        consuming everything up to and including the match. Returns the
        text before the match (i.e. the output produced since the last
        expect() call)."""
        to = timeout if timeout is not None else self.timeout
        deadline = time.time() + to
        rx = re.compile(pattern)
        while True:
            m = rx.search(self.buf)
            if m:
                before = self.buf[: m.start()]
                self.buf = self.buf[m.end() :]
                self.transcript.append(before)
                return before
            if not self._drain(deadline):
                if time.time() >= deadline:
                    raise TdbTimeout(
                        "timeout waiting for %r; buffered output so far:\n%s"
                        % (pattern, self.buf)
                    )

    def send(self, line):
        os.write(self.master, (line + "\n").encode())

    def cmd(self, line, prompt=PROMPT, timeout=None):
        """Send one command line and return the output produced before
        the next prompt (i.e. that command's own output)."""
        self.send(line)
        return self.expect(prompt, timeout=timeout)

    def interrupt(self):
        """Send SIGINT to the tdb process itself (Ctrl+C at the terminal)."""
        self.proc.send_signal(signal.SIGINT)

    def close(self):
        # `q` only exit(0)s tdb itself - it does not kill the debuggee
        # first. A debuggee thread that our own all-stop synchronization
        # had parked with a real SIGSTOP (e.g. after `lock`, or mid
        # watchpoint sync) stays parked forever once ptrace detaches on
        # tracer exit, since nothing ever sends it SIGCONT - leaking a
        # stuck background process that competes for resources with (and
        # can otherwise confuse) later test runs. Always kill first.
        try:
            self.send("kill")
            self.expect(PROMPT, timeout=3)
        except Exception:
            pass
        try:
            self.send("q")
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=3)
            except Exception:
                pass
        finally:
            try:
                os.close(self.master)
            except OSError:
                pass


# --- assertion helpers -----------------------------------------------

def check(condition, msg):
    if not condition:
        raise AssertionError(msg)


def check_contains(text, substr, label=""):
    check(substr in text, "%s: expected to find %r in output:\n%s" % (label, substr, text))


def check_not_contains(text, substr, label=""):
    check(substr not in text, "%s: expected NOT to find %r in output:\n%s" % (label, substr, text))


def check_regex(text, pattern, label=""):
    m = re.search(pattern, text)
    check(m is not None, "%s: expected pattern %r to match output:\n%s" % (label, pattern, text))
    return m


def extract(text, pattern, group=1, label=""):
    m = re.search(pattern, text)
    check(m is not None, "%s: expected pattern %r to match output:\n%s" % (label, pattern, text))
    return m.group(group)


# --- reporting ---------------------------------------------------------

class Reporter:
    """Records PASS/FAIL/ERROR/SKIP per spec test ID. A step() failure
    raises so the calling scenario can stop (state is now unknown) -
    the section runner is expected to catch that at the section level
    and mark remaining steps as SKIP."""

    def __init__(self, section):
        self.section = section
        self.results = []  # list of (test_id, status, message)

    def step(self, test_id, description, fn):
        try:
            fn()
        except AssertionError as e:
            self.results.append((test_id, "FAIL", "%s: %s" % (description, e)))
            raise
        except TdbTimeout as e:
            self.results.append((test_id, "FAIL", "%s: %s" % (description, e)))
            raise
        except Exception as e:
            self.results.append((test_id, "ERROR", "%s: %r" % (description, e)))
            raise
        else:
            self.results.append((test_id, "PASS", description))

    def skip(self, test_id, description, reason="not reached (earlier step in this scenario failed)"):
        self.results.append((test_id, "SKIP", "%s (%s)" % (description, reason)))


def run_scenario(r, steps, session_factory=Session):
    """Run a list of (test_id, description, fn(session)) against one
    fresh Session, stopping on the first failure (later steps in the
    same list depend on state the failed step was supposed to reach,
    so running them would just produce confusing secondary failures -
    Reporter.step() already recorded the real one)."""
    s = session_factory()
    try:
        for test_id, desc, fn in steps:
            r.step(test_id, desc, lambda fn=fn: fn(s))
    except Exception:
        pass
    finally:
        s.close()
