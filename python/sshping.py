#!/usr/bin/env python3
"""
sshping - measure character-echo latency and transfer throughput of an
interactive ssh session.  Python port of https://github.com/spook/sshping

MIT License, see LICENSE in the top-level directory.

Differences from the C++ version:
  * The default echo command is "stty raw -echo; cat", so each character is
    echoed by a remote process (as in a shell or editor) rather than by the
    remote kernel's terminal driver.  Use -e 'cat > /dev/null' for the old
    kernel-echo measurement.
  * ssh-Login-Time is measured until the remote shell actually answers,
    instead of including a fixed 1.3 s wait for login output to stop.
  * The server's host key is checked against known_hosts.  A changed key is
    an error; an unknown key is a warning (an error with --strict-host-key).
  * The speed test streams the data over a single ssh channel each way
    (cat > FILE, then cat FILE) instead of repeated 1 MB scp transfers, and
    the remote file is created with mktemp and removed afterwards.
  * Progress, warnings and -v messages go to stderr; stdout carries only
    the results.  The exit status is non-zero if any test fails.
  * Accounts without a shell, such as rsync.net's, which run only a fixed
    list of commands, are detected.  They get the C++ version's behavior
    (login ends when output stops, the terminal driver echoes) and an SFTP
    speed test, with a warning.
  * "Std-Deviation" replaces "Average-Deviation", which was always the
    sample standard deviation.
"""

import argparse
import base64
import getpass
import hashlib
import logging
import os
import secrets
import shlex
import socket
import statistics
import string
import sys
import time

try:
    import paramiko
except ImportError:
    sys.exit("*** sshping requires paramiko: pip install paramiko")

DEFAULT_ECHO_CMD = "stty raw -echo; cat"
DEFAULT_COUNT = 1000
DEFAULT_SIZE_MB = 8
DEFAULT_CONNECT_TIME = 10
MEGA = 1_000_000
GIGA = 1_000_000_000

ECHO_TIMEOUT = 5.0           # seconds to wait for a single echoed character
SHELL_TIMEOUT = 30.0         # seconds to wait for the login shell to answer
LOGIN_QUIET = 1.3            # seconds of quiet that end login without a shell
SETTLE_MIN = 0.5             # seconds of quiet before the echo test starts
TRANSFER_TIMEOUT = 60.0      # seconds without progress before a transfer fails
READY_MARK = b"SSHPING_READY"

EXIT_TEST_FAILED = 1
EXIT_USAGE = 2
EXIT_CONNECT_FAILED = 255

PREFIXES = {-9: "n", -6: "u", -3: "m", 0: "", 3: "k", 6: "M", 9: "G",
            12: "T", 15: "P", 18: "E"}

verbosity = 0


class SSHPingError(Exception):
    def __init__(self, msg, exit_code=EXIT_TEST_FAILED):
        super().__init__(msg)
        self.exit_code = exit_code


def now():
    return time.perf_counter_ns()


def verbose(msg, level=1):
    if verbosity >= level:
        print(msg, file=sys.stderr, flush=True)


def warn(msg):
    print(f"-*- Warning: {msg}", file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# Formatting and statistics
# ----------------------------------------------------------------------------

def fmtnum(n, scale, unit, human=False, delimited=False):
    """Format integer n, measured in units of 10**scale * unit.

    fmtnum(1234567, -9, "s")             -> "1234567 ns"
    fmtnum(1234567, -9, "s", delimited)  -> "1,234,567 ns"
    fmtnum(1234567, -9, "s", human)      -> "1.23 ms"
    """
    n = int(round(n))
    if not human:
        num = f"{n:,}" if delimited else str(n)
        return f"{num} {PREFIXES[scale]}{unit}"

    # Three significant digits: x.xx, xx.x or xxx, then the SI prefix
    f, p = float(n), scale
    while f >= 1000 and p + 3 in PREFIXES:
        f /= 1000
        p += 3
    if f < 9.995:
        num = f"{f:.2f}"
    elif f < 99.95:
        num = f"{f:.1f}"
    elif f < 999.5 or p + 3 not in PREFIXES:
        num = f"{f:.0f}"
    else:  # rounds up to 1000, so move to the next prefix
        p += 3
        num = f"{f / 1000:.2f}"
    return f"{num} {PREFIXES[p]}{unit}"


def latency_stats(latencies):
    """Summary statistics (all in ns) for a list of latencies."""
    return {
        "min":    min(latencies),
        "median": statistics.median(latencies),
        "mean":   statistics.fmean(latencies),
        "stdev":  statistics.stdev(latencies) if len(latencies) > 1 else 0,
        "max":    max(latencies),
    }


class Reporter:
    """Prints results as RFC-2822 style 'Label: value unit' lines."""

    def __init__(self, human=False, delimited=False):
        self.human = human
        self.delimited = delimited

    def line(self, label, n, scale, unit):
        num, _, units = fmtnum(n, scale, unit, self.human,
                               self.delimited).partition(" ")
        print(f"{label + ':':<19}{num:>15} {units}", flush=True)


# ----------------------------------------------------------------------------
# Target and configuration
# ----------------------------------------------------------------------------

def parse_target(target):
    """Split [user@]host[:port] into (user, host, port).

    IPv6 addresses may be given bare (no port) or in brackets: [::1]:2222.
    user and port are None when not given.
    """
    user, _, hostport = target.rpartition("@")
    port = None
    if hostport.startswith("["):
        host, sep, rest = hostport[1:].partition("]")
        if not sep:
            raise SSHPingError("Unbalanced IPv6 address brackets", EXIT_USAGE)
        if rest:
            if not rest.startswith(":"):
                raise SSHPingError(f"Bad target address {target}", EXIT_USAGE)
            port = rest[1:] or None
    elif hostport.count(":") == 1:
        host, _, port = hostport.partition(":")
        port = port or None
    else:
        host = hostport  # plain host name, or bare IPv6 address
    if not host:
        raise SSHPingError("Missing target address", EXIT_USAGE)
    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise SSHPingError("Bad port, must be integer from 1 to 65535",
                               EXIT_USAGE)
        port = int(port)
    return user or None, host, port


def lookup_ssh_config(path, host):
    """Return the ssh config options for host from path, or ~/.ssh/config."""
    config = paramiko.SSHConfig()
    if path is None:
        path = os.path.expanduser("~/.ssh/config")
        if not os.path.exists(path):
            return config.lookup(host)
    try:
        with open(path) as f:
            config.parse(f)
    except OSError as e:
        raise SSHPingError(f"Cannot read ssh config file: {e}", EXIT_USAGE)
    return config.lookup(host)


# ----------------------------------------------------------------------------
# Connection, host key check and authentication
# ----------------------------------------------------------------------------

class PromptClock:
    """Tracks time spent waiting for the user to type, so it can be excluded
    from the login time."""

    def __init__(self):
        self.excluded_ns = 0

    def prompt(self, func, *args):
        t = now()
        try:
            return func(*args)
        except EOFError:
            return None
        finally:
            self.excluded_ns += now() - t


def open_socket(host, port, proxycommand, bindaddr, timeout):
    if proxycommand:
        verbose(f"+++ Using ProxyCommand: {proxycommand}")
        return paramiko.ProxyCommand(proxycommand)
    try:
        sock = socket.create_connection(
            (host, port), timeout=timeout,
            source_address=(bindaddr, 0) if bindaddr else None)
    except OSError as e:
        raise SSHPingError(f"Error connecting to {host}:{port}: {e}",
                           EXIT_CONNECT_FAILED)
    # Like OpenSSH for interactive sessions: send each keystroke immediately
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def fingerprint(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def check_host_key(transport, host, port, strict):
    key = transport.get_remote_server_key()
    name = host if port == 22 else f"[{host}]:{port}"
    known = paramiko.HostKeys()
    for path in ("~/.ssh/known_hosts", "/etc/ssh/ssh_known_hosts"):
        try:
            known.load(os.path.expanduser(path))
        except OSError:
            pass
    entry = known.lookup(name)
    desc = f"{key.get_name()} {fingerprint(key)}"
    if entry is not None and key.get_name() in entry:
        if entry[key.get_name()] == key:
            verbose(f"+++ Host key for {name} matches known_hosts ({desc})")
            return
        raise SSHPingError(
            f"HOST KEY FOR {name} HAS CHANGED, possible man-in-the-middle "
            f"attack!  Server sent {desc}", EXIT_CONNECT_FAILED)
    msg = f"host key for {name} is not in known_hosts ({desc})"
    if strict:
        raise SSHPingError(msg[0].upper() + msg[1:], EXIT_CONNECT_FAILED)
    warn(msg)


def candidate_keys(identities, clock):
    """Yield (description, key) for each key to try, in OpenSSH's order:
    identity files given with -i or in ssh config, agent keys, default keys."""
    defaults = [os.path.expanduser(f"~/.ssh/id_{t}")
                for t in ("ed25519", "ecdsa", "rsa")]
    seen = set()
    files = [os.path.expanduser(p) for p in identities]

    for path in files:
        if path not in seen:
            seen.add(path)
            key = load_key(path, clock, required=True)
            if key:
                yield path, key
    try:
        for key in paramiko.Agent().get_keys():
            yield f"agent key {fingerprint(key)}", key
    except paramiko.SSHException as e:
        verbose(f"  * Cannot use ssh agent: {e}")
    for path in defaults:
        if path not in seen and os.path.exists(path):
            seen.add(path)
            key = load_key(path, clock)
            if key:
                yield path, key


def load_key(path, clock, required=False):
    try:
        try:
            return paramiko.PKey.from_path(path)
        except paramiko.PasswordRequiredException:
            phrase = clock.prompt(getpass.getpass,
                                  f"Enter passphrase for key '{path}': ")
            if not phrase:
                return None
            return paramiko.PKey.from_path(path, phrase)
    except (OSError, paramiko.SSHException, ValueError) as e:
        if required:
            warn(f"cannot load identity file {path}: {e}")
        else:
            verbose(f"  * Skipping key {path}: {e}")
        return None


def authenticate(transport, user, host, password, identities, clock):
    """Authenticate with each method the server allows, in the order
    none, publickey, keyboard-interactive, password."""
    state = {"password": password}

    def try_publickey():
        for desc, key in candidate_keys(identities, clock):
            try:
                remaining = transport.auth_publickey(user, key)
                verbose(f"+++ Public key accepted: {desc}")
                return remaining
            except paramiko.BadAuthenticationType:
                raise
            except paramiko.AuthenticationException:
                verbose(f"  * Public key rejected: {desc}")
        return None

    def kbdint_handler(title, instructions, prompts):
        for text in (title, instructions):
            if text:
                print(text, file=sys.stderr)
        answers = []
        for prompt, echo in prompts:
            if echo:
                answer = clock.prompt(input, prompt)
            elif state["password"] is not None:
                answer = state["password"]
            else:
                answer = clock.prompt(getpass.getpass, prompt)
                state["password"] = answer
            answers.append(answer or "")
        return answers

    def try_kbdint():
        return transport.auth_interactive(user, kbdint_handler)

    def try_password():
        if state["password"] is None:
            state["password"] = clock.prompt(
                getpass.getpass, f"Enter password for {user}@{host}: ")
        if state["password"] is None:
            return None
        return transport.auth_password(user, state["password"])

    methods = {"publickey": try_publickey,
               "keyboard-interactive": try_kbdint,
               "password": try_password}

    try:
        allowed = transport.auth_none(user)
    except paramiko.BadAuthenticationType as e:
        allowed = e.allowed_types
    tried = set()
    while not transport.is_authenticated():
        method = next((m for m in methods if m in allowed and m not in tried),
                      None)
        if method is None:
            raise SSHPingError(
                f"Cannot authenticate user {user} (server allows: "
                f"{', '.join(allowed) or 'nothing'})", EXIT_CONNECT_FAILED)
        tried.add(method)
        try:
            remaining = methods[method]()
        except paramiko.BadAuthenticationType as e:
            allowed = e.allowed_types
            continue
        except paramiko.AuthenticationException as e:
            verbose(f"  + Authentication by {method} failed: {e}")
            continue
        if remaining:  # partial success, server wants another method
            verbose(f"  + Further authentication required: "
                    f"{', '.join(remaining)}")
            allowed = remaining
    verbose(f"+++ Authenticated as {user}")


# ----------------------------------------------------------------------------
# Login shell and echo test
# ----------------------------------------------------------------------------

def read_until(chan, marker, timeout):
    """Read from chan until marker has been received."""
    deadline = time.monotonic() + timeout
    buf = b""
    while marker not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        chan.settimeout(remaining)
        data = chan.recv(4096)
        if not data:
            raise EOFError()
        buf = buf[-len(marker):] + data


def drain_until_quiet(chan, quiet, max_wait):
    """Discard output until none arrives for `quiet` seconds.  Returns the
    time the last output arrived, or None if there was none.  Raises
    EOFError if the channel closes."""
    deadline = time.monotonic() + max_wait
    last = None
    chan.settimeout(quiet)
    while True:
        try:
            data = chan.recv(4096)
        except socket.timeout:
            return last
        if not data:
            raise EOFError()
        last = now()
        if time.monotonic() > deadline:
            raise SSHPingError("Remote session keeps producing output; "
                               "cannot start the echo test")


def has_posix_shell(transport):
    """Whether the account's commands run under a real shell.  Restricted
    accounts, such as rsync.net's, run a fixed list of commands without one.
    Only a shell removes the empty quotes."""
    try:
        status, out, _ = remote_run(transport, 'echo SSHPING_""READY',
                                    timeout=SHELL_TIMEOUT)
    except (paramiko.SSHException, OSError, SSHPingError) as e:
        verbose(f"  * Shell check failed: {e}")
        return False
    return status == 0 and READY_MARK.decode() in out


def open_pty_session(transport):
    chan = transport.open_session()
    chan.get_pty(term="xterm", width=80, height=24)
    chan.invoke_shell()
    return chan


def open_login_shell(transport):
    """Start an interactive shell on a pty and wait until it answers.
    Returns the channel, or None if the shell did not answer in time."""
    chan = open_pty_session(transport)
    # The empty quotes keep the terminal's echo of this line from matching.
    # Commands start with a space to keep them out of the shell history.
    chan.sendall(b' echo SSHPING_""READY\n')
    try:
        read_until(chan, READY_MARK, SHELL_TIMEOUT)
    except socket.timeout:
        chan.close()
        return None
    except EOFError:
        raise SSHPingError("Login shell exited", EXIT_CONNECT_FAILED)
    verbose("+++ Login shell established")
    return chan


def open_shellless_session(transport):
    """For accounts without a usable shell, do what the C++ sshping does:
    open a pty session and wait for login output to stop.  Returns the
    channel and the time the session was ready (when its last output
    arrived)."""
    chan = open_pty_session(transport)
    ready = now()
    try:
        last = drain_until_quiet(chan, LOGIN_QUIET, max_wait=SHELL_TIMEOUT)
    except EOFError:
        raise SSHPingError("Remote host closed the terminal session",
                           EXIT_CONNECT_FAILED)
    verbose("+++ Terminal session established (no shell)")
    return chan, last or ready


class Progress:
    """Live 'Ping n/N: latency' display on stderr, if it is a terminal."""

    def __init__(self, total, reporter):
        self.total = total or "-"
        self.reporter = reporter
        self.enabled = sys.stderr.isatty() or verbosity >= 2
        self.last = 0

    def update(self, n, latency):
        if not self.enabled:
            return
        t = now()
        if verbosity >= 2 or t - self.last > GIGA // 10:
            self.last = t
            lat = fmtnum(latency, -9, "s", self.reporter.human,
                         self.reporter.delimited)
            end = "\n" if verbosity >= 2 else ""
            print(f"\rPing {n}/{self.total}: {lat:>16}  ", end=end,
                  file=sys.stderr, flush=True)

    def done(self):
        if self.enabled and verbosity < 2:
            print("\r" + " " * 40 + "\r", end="", file=sys.stderr, flush=True)


def start_echo_responder(chan, echo_cmd):
    # The command line comes straight back from the terminal driver, which
    # gives a rough round-trip time; then wait for output to stop so the
    # responder is running before timing starts.
    t = now()
    chan.sendall((" " + echo_cmd + "\n").encode())
    chan.settimeout(ECHO_TIMEOUT)
    try:
        if not chan.recv(4096):
            raise SSHPingError("Remote shell exited")
    except socket.timeout:
        raise SSHPingError("No response from remote shell")
    rtt = (now() - t) / GIGA
    try:
        drain_until_quiet(chan, quiet=max(SETTLE_MIN, 4 * rtt), max_wait=15)
    except EOFError:
        raise SSHPingError("Remote shell exited during echo setup")
    verbose(f"+++ Echo responder started: {echo_cmd}")


def run_echo_test(chan, echo_cmd, count, time_limit, reporter, ping_summary):
    """Time single-character echoes.  With echo_cmd None there is no shell
    to run a responder, and the remote terminal driver does the echoing."""
    if echo_cmd is not None:
        start_echo_responder(chan, echo_cmd)

    chars = string.ascii_letters.encode()
    latencies = []
    progress = Progress(count, reporter)
    deadline = now() + time_limit * GIGA if time_limit else None
    chan.settimeout(ECHO_TIMEOUT)
    error = None
    try:
        while ((not count or len(latencies) < count)
               and (deadline is None or now() < deadline)):
            n = len(latencies)
            c = chars[n % len(chars):][:1]
            tw = now()
            chan.sendall(c)
            r = chan.recv(1)
            tr = now()
            if r != c:
                error = (f"echo failed, sent {c!r} yet got {r!r}" if r
                         else "the remote session closed")
                break
            latencies.append(tr - tw)
            progress.update(n + 1, tr - tw)
    except socket.timeout:
        error = f"no echo within {ECHO_TIMEOUT:.0f} s"
    finally:
        progress.done()
        chan.close()  # hangs up the remote session, ending the responder
    if error:
        if echo_cmd is not None or not latencies:
            raise SSHPingError(f"{error[0].upper()}{error[1:]} after "
                               f"{len(latencies)} characters")
        # Without a shell, nothing reads what we type, so the remote
        # terminal's input buffer can fill up and stop echoing
        warn(f"echo stopped after {len(latencies)} characters: {error}.  "
             "The remote terminal's input buffer is probably full; use -c "
             "to send fewer characters")
    verbose("+++ Echo test finished")

    if len(latencies) < 13:
        warn("too few echos to be statistically valid")
    s = latency_stats(latencies)
    reporter.line("Minimum-Latency", s["min"], -9, "s")
    reporter.line("Median-Latency", s["median"], -9, "s")
    reporter.line("Average-Latency", s["mean"], -9, "s")
    reporter.line("Std-Deviation", s["stdev"], -9, "s")
    reporter.line("Maximum-Latency", s["max"], -9, "s")
    reporter.line("Echo-Count", len(latencies), 0, "B")
    if ping_summary:
        ms = [s[k] / MEGA for k in ("min", "mean", "max", "stdev")]
        print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % tuple(ms))


# ----------------------------------------------------------------------------
# Speed tests
# ----------------------------------------------------------------------------

def remote_run(transport, command, timeout=TRANSFER_TIMEOUT):
    """Run a command on its own channel; return (status, stdout, stderr)."""
    chan = transport.open_session()
    chan.settimeout(timeout)
    chan.exec_command(command)
    stdout = chan.makefile("rb").read().decode(errors="replace")
    stderr = chan.makefile_stderr("rb").read().decode(errors="replace")
    status = wait_exit_status(chan, timeout)
    chan.close()
    return status, stdout, stderr


def wait_exit_status(chan, timeout):
    if not chan.status_event.wait(timeout):
        raise SSHPingError("Timed out waiting for remote command to finish")
    return chan.recv_exit_status()


def remote_error(chan):
    err = b""
    while chan.recv_stderr_ready():
        err += chan.recv_stderr(4096)
    return err.decode(errors="replace").strip()


def make_payload():
    """1 MB of random printable characters."""
    table = bytes(32 + (i & 0x3f) for i in range(256))
    return os.urandom(MEGA).translate(table)


def report_transfer(reporter, direction, nbytes, elapsed_ns):
    reporter.line(f"{direction}-Size", nbytes, 0, "B")
    reporter.line(f"{direction}-Rate", nbytes * GIGA / max(elapsed_ns, 1),
                  0, "B/s")


def run_upload_test(transport, remfile, size_mb, reporter):
    verbose(f"+++ Upload test started, remote file is {remfile}")
    payload = make_payload()
    chan = transport.open_session()
    chan.settimeout(TRANSFER_TIMEOUT)
    chan.exec_command(f"cat > {shlex.quote(remfile)}")
    t2 = now()
    try:
        for _ in range(size_mb):
            chan.sendall(payload)
        chan.shutdown_write()
        status = wait_exit_status(chan, TRANSFER_TIMEOUT)
    except (socket.timeout, OSError) as e:
        # Usually the remote command failed and closed the channel early
        if chan.status_event.wait(5):
            status = chan.recv_exit_status()
            raise SSHPingError(f"Upload failed (exit status {status}): "
                               f"{remote_error(chan) or e}")
        raise SSHPingError(f"Upload failed: {e}")
    t3 = now()
    if status != 0:
        raise SSHPingError(f"Upload failed (exit status {status}): "
                           f"{remote_error(chan)}")
    chan.close()
    report_transfer(reporter, "Upload", size_mb * MEGA, t3 - t2)
    verbose("+++ Upload test completed")


def run_download_test(transport, remfile, size_mb, reporter):
    verbose(f"+++ Download test started, remote file is {remfile}")
    expected = size_mb * MEGA
    chan = transport.open_session()
    chan.settimeout(TRANSFER_TIMEOUT)
    chan.exec_command(f"cat {shlex.quote(remfile)}")
    t2 = now()
    received = 0
    try:
        while True:
            data = chan.recv(1 << 20)
            if not data:
                break
            received += len(data)
        t3 = now()
        status = wait_exit_status(chan, TRANSFER_TIMEOUT)
    except socket.timeout:
        raise SSHPingError(f"Download stalled after {received} bytes")
    if status != 0:
        raise SSHPingError(f"Download failed (exit status {status}): "
                           f"{remote_error(chan)}")
    chan.close()
    if received != expected:
        raise SSHPingError(f"Download got {received} bytes, "
                           f"expected {expected}")
    report_transfer(reporter, "Download", received, t3 - t2)
    verbose("+++ Download test completed")


def prepare_remote_file(transport, path):
    """Return (path, remove_afterwards).  Without -z, create a private
    temporary file with mktemp; with -z, remove the file afterwards only if
    it did not exist before."""
    if path is None:
        status, out, err = remote_run(transport,
                                      "mktemp /tmp/sshping-XXXXXXXX")
        if status != 0 or not out.strip():
            raise SSHPingError(f"Cannot create remote temp file: "
                               f"{err.strip() or 'mktemp failed'}")
        return out.strip(), True
    status, _, _ = remote_run(transport, f"test -e {shlex.quote(path)}")
    return path, status != 0


def run_sftp_speed_tests(transport, remfile, size_mb, reporter):
    """Speed test over SFTP, for accounts that cannot run cat > FILE or
    mktemp.  Without -z the file gets a random name in the SFTP starting
    directory (normally home); with -z it is removed afterwards only if it
    did not exist before."""
    try:
        sftp = paramiko.SFTPClient.from_transport(transport)
    except (paramiko.SSHException, OSError) as e:
        raise SSHPingError(f"Cannot start SFTP for the speed test: {e}")
    sftp.get_channel().settimeout(TRANSFER_TIMEOUT)
    if remfile is None:
        remfile, remove = f"sshping-{secrets.token_hex(8)}.tmp", True
    else:
        try:
            sftp.stat(remfile)
            remove = False
        except FileNotFoundError:
            remove = True
        except (OSError, paramiko.SSHException) as e:
            sftp.close()
            raise SSHPingError(f"Cannot check remote file {remfile}: {e}")
    expected = size_mb * MEGA
    try:
        verbose(f"+++ SFTP upload test started, remote file is {remfile}")
        payload = make_payload()
        try:
            t2 = now()
            with sftp.open(remfile, "wb") as f:
                f.set_pipelined(True)
                for _ in range(size_mb):
                    f.write(payload)
            t3 = now()  # closing waits until every write is acknowledged
        except (OSError, paramiko.SSHException) as e:
            raise SSHPingError(f"SFTP upload to {remfile} failed: {e}")
        report_transfer(reporter, "Upload", expected, t3 - t2)

        verbose("+++ SFTP download test started")
        received = 0
        try:
            t2 = now()
            with sftp.open(remfile, "rb") as f:
                f.prefetch(expected)
                while True:
                    data = f.read(1 << 20)
                    if not data:
                        break
                    received += len(data)
            t3 = now()
        except (OSError, paramiko.SSHException) as e:
            raise SSHPingError(f"SFTP download of {remfile} failed after "
                               f"{received} bytes: {e}")
        if received != expected:
            raise SSHPingError(f"Download got {received} bytes, "
                               f"expected {expected}")
        report_transfer(reporter, "Download", received, t3 - t2)
        verbose("+++ SFTP speed test completed")
    finally:
        if remove:
            try:
                sftp.remove(remfile)
            except (OSError, paramiko.SSHException):
                warn(f"could not remove remote file {remfile}")
        sftp.close()


def run_speed_tests(transport, remfile, size_mb, reporter):
    remfile, remove = prepare_remote_file(transport, remfile)
    try:
        run_upload_test(transport, remfile, size_mb, reporter)
        run_download_test(transport, remfile, size_mb, reporter)
    finally:
        if remove:
            try:
                remote_run(transport, f"rm -f {shlex.quote(remfile)}")
            except (paramiko.SSHException, OSError, SSHPingError):
                warn(f"could not remove remote file {remfile}")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def positive_int(text):
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer: "
                                         f"{text!r}")
    return value


def nonnegative_int(text):
    try:
        value = int(text)
    except ValueError:
        value = -1
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be a non-negative integer: "
                                         f"{text!r}")
    return value


def runtests(text):
    if not text or set(text) - {"e", "s"}:
        raise argparse.ArgumentTypeError("use e (echo), s (speed) or es")
    return text


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="sshping",
        usage="%(prog)s [options] [user@]addr[:port]",
        description="SSH-based ping that measures interactive character echo "
                    "latency and file transfer throughput.  Pronounced "
                    "\"shipping\".")
    p.add_argument("target", help="[user@]addr[:port]; IPv6 as [addr]:port")
    p.add_argument("-b", "--bindaddr", metavar="IP",
                   help="bind to this source address")
    p.add_argument("-c", "--count", metavar="NCHARS", type=positive_int,
                   help=f"number of characters to echo, default "
                        f"{DEFAULT_COUNT}")
    p.add_argument("-d", "--delimited", action="store_true",
                   help="use delimiters in big numbers, eg 1,234,567")
    p.add_argument("-e", "--echocmd", metavar="CMD",
                   help=f"remote echo command, default: {DEFAULT_ECHO_CMD}; "
                        "use 'cat > /dev/null' to have the remote terminal "
                        "driver echo instead of a process.  Ignored on hosts "
                        "without a shell, where the terminal driver echoes")
    p.add_argument("-F", "--config-file", metavar="FILE",
                   help="read ssh options from FILE, default ~/.ssh/config")
    p.add_argument("-H", "--human-readable", action="store_true",
                   help="use flesh-friendly units")
    p.add_argument("-i", "--identity", metavar="FILE",
                   help="identity file, ie ssh private keyfile")
    p.add_argument("-k", "--keyboard-wait", action="store_true",
                   help="wait for Enter before exiting")
    p.add_argument("-p", "--password", metavar="PWD",
                   help="use password PWD (can be seen, use with care)")
    p.add_argument("-P", "--ping-summary", action="store_true",
                   help="append measurements in ping-like rtt line format")
    p.add_argument("-r", "--runtests", metavar="e|s", type=runtests,
                   default="es",
                   help="run tests e=echo s=speed; default es=both")
    p.add_argument("-s", "--size", metavar="MB", type=positive_int,
                   default=DEFAULT_SIZE_MB,
                   help=f"for speed test, send/recv MB megabytes; "
                        f"default {DEFAULT_SIZE_MB}")
    p.add_argument("-t", "--time", metavar="SECS", type=positive_int,
                   help="time limit for echo test")
    p.add_argument("-T", "--connect-time", metavar="SECS",
                   type=nonnegative_int, default=DEFAULT_CONNECT_TIME,
                   help=f"time limit for ssh connection, 0 for none; "
                        f"default {DEFAULT_CONNECT_TIME}")
    p.add_argument("--strict-host-key", action="store_true",
                   help="fail if the host key is not in known_hosts")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="show more output; -vv shows every ping, "
                        "-vvv adds ssh protocol debugging")
    p.add_argument("-z", "--remote", metavar="FILE",
                   help="remote file for up/download tests; default is a "
                        "new mktemp file in /tmp (on hosts without a shell, "
                        "a randomly named file in the SFTP home directory), "
                        "removed afterwards")
    args = p.parse_args(argv)
    if args.count is None and args.time is None:
        args.count = DEFAULT_COUNT
    return args


def run(args):
    global verbosity
    verbosity = args.verbose
    if verbosity >= 3:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    user, host, port = parse_target(args.target)
    cfg = lookup_ssh_config(args.config_file, host)
    if "proxyjump" in cfg:
        warn("ProxyJump in ssh config is not supported, ignoring it")
    hostname = cfg.get("hostname", host)
    port = port or int(cfg.get("port", 22))
    user = user or cfg.get("user") or getpass.getuser()
    identities = ([args.identity] if args.identity
                  else cfg.get("identityfile", []))
    timeout = args.connect_time or None
    reporter = Reporter(args.human_readable, args.delimited)

    echo_cmd = args.echocmd or DEFAULT_ECHO_CMD
    verbose(f"User: {user}\nHost: {hostname}\nPort: {port}\n"
            f"Echo: {echo_cmd}\n Cfg: {args.config_file or '--default--'}"
            "\n")
    verbose(f"+++ Attempting connection to {hostname}:{port} as user "
            f"'{user}'")

    clock = PromptClock()
    t0 = now()
    sock = open_socket(hostname, port, cfg.get("proxycommand"), args.bindaddr,
                       timeout)
    transport = paramiko.Transport(sock)
    try:
        try:
            if timeout:
                transport.banner_timeout = timeout
            transport.start_client(timeout=timeout)
            verbose(f"+++ Connected to {hostname}:{port}")
            check_host_key(transport, hostname, port, args.strict_host_key)
            authenticate(transport, user, hostname, args.password, identities,
                         clock)
            # Checking for a shell and waiting for a shell that never
            # answers don't count toward the login time
            t = now()
            shell = has_posix_shell(transport)
            clock.excluded_ns += now() - t
            t = now()
            chan = open_login_shell(transport) if shell else None
            t1 = now()
            if chan is None:
                clock.excluded_ns += t1 - t
                notes = ["login time ends when login output stops"]
                if "e" in args.runtests:
                    notes.append("the remote terminal driver echoes"
                                 + (" (-e ignored)" if args.echocmd else ""))
                if "s" in args.runtests and not shell:
                    notes.append("the speed test uses SFTP")
                reason = (f"login shell did not answer within "
                          f"{SHELL_TIMEOUT:.0f} s" if shell else
                          "remote account has no shell (restricted, like "
                          "rsync.net?)")
                warn(f"{reason}: {', '.join(notes)}")
                chan, t1 = open_shellless_session(transport)
                echo_cmd = None
        except (paramiko.SSHException, OSError, EOFError) as e:
            raise SSHPingError(f"ssh connection failed: {e}",
                               EXIT_CONNECT_FAILED)
        reporter.line("ssh-Login-Time", t1 - t0 - clock.excluded_ns, -9, "s")

        try:
            if "e" in args.runtests:
                run_echo_test(chan, echo_cmd, args.count, args.time,
                              reporter, args.ping_summary)
            else:
                chan.close()
            if "s" in args.runtests and shell:
                run_speed_tests(transport, args.remote, args.size, reporter)
            elif "s" in args.runtests:
                run_sftp_speed_tests(transport, args.remote, args.size,
                                     reporter)
        except (paramiko.SSHException, OSError) as e:
            raise SSHPingError(f"Test failed: {e}")
    finally:
        transport.close()
        verbose("+++ Disconnected")
    return 0


def main(argv=None):
    args = parse_args(argv)
    try:
        status = run(args)
    except SSHPingError as e:
        print(f"*** {e}", file=sys.stderr)
        status = e.exit_code
    except KeyboardInterrupt:
        print(file=sys.stderr)
        status = 130
    if args.keyboard_wait:
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass
    return status


if __name__ == "__main__":
    sys.exit(main())
