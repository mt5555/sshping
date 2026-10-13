#!/usr/bin/env python3
"""End-to-end tests of sshping.py against fake ssh servers built with
paramiko, mainly one that behaves like a restricted account such as
rsync.net's.

What the fake copies from rsync.net, as observed with a real account:
there is no interactive shell, but a terminal session can be opened and its
terminal driver echoes.  Commands come from a fixed list (no sh, stty or
mktemp).  The command handler removes quotes and runs commands separated by
';' like a shell does.  /tmp exists, and "dd of=FILE" and "cat FILE" work.
"""

import contextlib
import io
import os
import re
import shlex
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

import paramiko

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sshping  # noqa: E402

USER = "tester"
PASSWORD = "correct horse"
HOST_KEY = None


def setUpModule():
    global HOST_KEY
    HOST_KEY = paramiko.RSAKey.generate(2048)


def split_commands(command):
    """Split a command line the way rsync.net's handler appears to: words
    with quotes removed, and ';' separating commands.  No other shell
    syntax: no redirection, variables or arithmetic."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=";")
    lex.whitespace_split = True
    commands = [[]]
    for word in lex:
        if word == ";":
            commands.append([])
        else:
            commands[-1].append(word)
    return [c for c in commands if c]


class CommandFailed(Exception):
    pass


class RestrictedServer(paramiko.ServerInterface):
    """An rsync.net-style account.  The filesystem lives in `root`; the home
    directory is root/home, and /tmp exists only if root/tmp does."""

    ALLOWED = {"cat", "dd", "echo", "test", "tree", "tail", "cp", "ls",
               "mkdir", "pwd", "chmod", "ln", "mv", "rm", "rmdir", "touch",
               "find", "df", "date", "stat", "cksum"}
    has_shell = False

    def __init__(self, root, echo_limit=None):
        self.root = root
        self.echo_limit = echo_limit
        self.exec_commands = []
        os.makedirs(os.path.join(root, "home"), exist_ok=True)

    # --- authentication and channels

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if username == USER and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        # No interactive shell: nothing reads the terminal, so only its
        # driver's echo comes back
        threading.Thread(target=self._terminal_echo, args=(channel,),
                         daemon=True).start()
        return True

    def _terminal_echo(self, chan):
        echoed = 0
        while True:
            data = chan.recv(1024)
            if not data:
                return
            if self.echo_limit is not None:  # input buffer full
                data = data[:max(0, self.echo_limit - echoed)]
            echoed += len(data)
            if data:
                chan.sendall(data.replace(b"\n", b"\r\n"))

    def check_channel_exec_request(self, channel, command):
        command = command.decode()
        self.exec_commands.append(command)
        threading.Thread(target=self._exec, args=(channel, command),
                         daemon=True).start()
        return True

    def _exec(self, chan, command):
        status = 0
        try:
            for words in split_commands(command):
                status = self._run(chan, words)
        except CommandFailed as e:
            chan.sendall_stderr(f"{e}\n".encode())
            status = 1
        chan.send_exit_status(status)
        # End with EOF rather than close(): closing can beat paramiko's
        # reply to the exec request, which the client sees as a failure
        chan.shutdown_write()

    # --- commands

    def _path(self, path):
        if not path.startswith("/"):
            path = "/home/" + path
        return os.path.join(self.root, os.path.normpath(path).lstrip("/"))

    def _stdin(self, chan):
        data = b""
        while True:
            chunk = chan.recv(65536)
            if not chunk:
                return data
            data += chunk

    def _run(self, chan, words):
        name, args = words[0], words[1:]
        if name == "sh" and self.has_shell:
            return self._sh(chan, args)
        if name not in self.ALLOWED:
            raise CommandFailed(f"Command not allowed: {name}")
        method = getattr(self, f"_cmd_{name}", None)
        if method is None:
            raise CommandFailed(f"fake server: {name} not implemented")
        return method(chan, args)

    def _cmd_echo(self, chan, args):
        chan.sendall((" ".join(args) + "\n").encode())
        return 0

    def _cmd_test(self, chan, args):
        if len(args) != 2:
            raise CommandFailed("fake server: test supports -e, -d, -w FILE")
        op, path = args[0], self._path(args[1])
        result = {"-e": os.path.exists, "-d": os.path.isdir,
                  "-w": lambda p: os.access(p, os.W_OK)}[op](path)
        return 0 if result else 1

    def _cmd_dd(self, chan, args):
        ops = dict(a.split("=", 1) for a in args)
        try:
            if "if" in ops:
                with open(self._path(ops["if"]), "rb") as f:
                    data = f.read()
            else:
                data = self._stdin(chan)
            if "of" in ops:
                with open(self._path(ops["of"]), "wb") as f:
                    f.write(data)
            else:
                chan.sendall(data)
        except OSError as e:
            raise CommandFailed(f"dd: {e.strerror}")
        chan.sendall_stderr(f"{len(data)} bytes transferred\n".encode())
        return 0

    def _cmd_cat(self, chan, args):
        for path in args:
            try:
                with open(self._path(path), "rb") as f:
                    chan.sendall(f.read())
            except OSError as e:
                raise CommandFailed(f"cat: {path}: {e.strerror}")
        return 0

    def _cmd_rm(self, chan, args):
        force = "-f" in args
        for path in (a for a in args if not a.startswith("-")):
            try:
                os.remove(self._path(path))
            except FileNotFoundError:
                if not force:
                    raise CommandFailed(f"rm: {path}: No such file")
        return 0

    def _sh(self, chan, args):
        """Just enough of sh -c for the tests: arithmetic expansion."""
        if args[:1] != ["-c"] or len(args) != 2:
            raise CommandFailed("fake server: only sh -c SCRIPT")
        script = re.sub(r"\$\(\((\d+)\*(\d+)\)\)",
                        lambda m: str(int(m[1]) * int(m[2])), args[1])
        status = 0
        for words in split_commands(script):
            status = self._run(chan, words)
        return status


class ShellWithoutTerminalServer(RestrictedServer):
    """Commands can run a real shell, but an interactive login never
    answers (a menu, or a login that hangs)."""
    has_shell = True


class FakeSSHServer:
    """Accepts ssh connections on localhost in a background thread."""

    def __init__(self, server):
        self.server = server
        self.transports = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(client)
            t.add_server_key(HOST_KEY)
            self.transports.append(t)
            try:
                t.start_server(server=self.server)
            except paramiko.SSHException:
                pass

    def close(self):
        self.sock.close()
        for t in self.transports:
            t.close()


class FakeServerTestCase(unittest.TestCase):
    server_class = RestrictedServer

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = os.path.join(tmp.name, "remote")
        self.local_home = os.path.join(tmp.name, "local")
        os.makedirs(os.path.join(self.root, "tmp"))
        os.mkdir(self.local_home)
        # Keep the waits short so the tests run quickly
        for name, value in (("LOGIN_QUIET", 0.2), ("ECHO_TIMEOUT", 0.5),
                            ("SHELL_TIMEOUT", 1.0)):
            patcher = mock.patch.object(sshping, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def start_server(self, **kwargs):
        self.server = self.server_class(self.root, **kwargs)
        self.ssh = FakeSSHServer(self.server)
        self.addCleanup(self.ssh.close)

    def remote_files(self):
        return sorted(os.path.relpath(os.path.join(d, f), self.root)
                      for d, _, files in os.walk(self.root) for f in files)

    def run_sshping(self, *args, password=PASSWORD):
        """Run sshping in-process with no local keys, agent or ssh config.
        Returns (exit status, {label: value} from stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        env = {"HOME": self.local_home, "SSH_AUTH_SOCK": ""}
        with mock.patch.dict(os.environ, env), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            status = sshping.main([*args, "-p", password,
                                   f"{USER}@127.0.0.1:{self.ssh.port}"])
        results = {}
        for line in out.getvalue().splitlines():
            label, sep, value = line.partition(":")
            if sep:
                results[label] = value.strip()
        return status, results, err.getvalue()


class TestFakeServer(FakeServerTestCase):
    """The fake restricted server must behave like the real rsync.net,
    or the other tests prove nothing."""

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.ssh.port))
        transport = paramiko.Transport(sock)
        self.addCleanup(transport.close)
        transport.start_client()
        transport.auth_password(USER, PASSWORD)
        return transport

    def test_behaves_like_rsync_net(self):
        self.start_server()
        t = self.connect()
        self.assertEqual(sshping.remote_run(t, 'echo SSHPING_""READY')[:2],
                         (0, "SSHPING_READY\n"))
        self.assertEqual(sshping.remote_run(t, "echo SSHPING; echo READY")
                         [:2], (0, "SSHPING\nREADY\n"))
        for command in (sshping.SHELL_CHECK, "stty -a", "mktemp"):
            status, _, err = sshping.remote_run(t, command)
            self.assertEqual(status, 1, command)
            self.assertIn("not allowed", err)
        self.assertEqual(sshping.remote_run(t, "test -w /tmp")[0], 0)
        self.assertFalse(sshping.has_shell(t))

    def test_shell_server_passes_the_shell_check(self):
        self.server_class = ShellWithoutTerminalServer
        self.start_server()
        self.assertTrue(sshping.has_shell(self.connect()))


class TestRestrictedAccount(FakeServerTestCase):

    def test_full_run(self):
        self.start_server()
        status, results, err = self.run_sshping("-c", "100", "-s", "2",
                                                "-e", "cat")
        self.assertEqual(status, 0, err)
        for label in ("ssh-Login-Time", "Minimum-Latency", "Median-Latency",
                      "Average-Latency", "Std-Deviation", "Maximum-Latency",
                      "Upload-Rate", "Download-Rate"):
            self.assertIn(label, results)
        self.assertEqual(results["Echo-Count"], "100 B")
        self.assertEqual(results["Upload-Size"], "2000000 B")
        self.assertEqual(results["Download-Size"], "2000000 B")
        self.assertIn("remote account has no shell", err)
        self.assertIn("(-e ignored)", err)

        # After the shell check, only allowed commands were run, and the
        # file went to /tmp and was removed
        check, *commands = self.server.exec_commands
        self.assertEqual(check, sshping.SHELL_CHECK)
        for command in commands:
            for words in split_commands(command):
                self.assertIn(words[0], RestrictedServer.ALLOWED, command)
        self.assertEqual(commands[0], "test -w /tmp")
        self.assertRegex(commands[1], r"^dd of=/tmp/sshping-[0-9a-f]{16}\.tmp ")
        self.assertEqual(self.remote_files(), [])

    def test_without_tmp_the_file_goes_in_home(self):
        os.rmdir(os.path.join(self.root, "tmp"))
        self.start_server()
        status, _, err = self.run_sshping("-r", "s", "-s", "1")
        self.assertEqual(status, 0, err)
        self.assertRegex(self.server.exec_commands[2],
                         r"^dd of=sshping-[0-9a-f]{16}\.tmp ")
        self.assertEqual(self.remote_files(), [])

    def test_existing_remote_file_is_kept(self):
        self.start_server()
        path = os.path.join(self.root, "home", "existing.tmp")
        with open(path, "w") as f:
            f.write("old")
        status, _, err = self.run_sshping("-r", "s", "-s", "1",
                                          "-z", "existing.tmp")
        self.assertEqual(status, 0, err)
        self.assertEqual(os.path.getsize(path), sshping.MEGA)

    def test_new_remote_file_is_removed(self):
        self.start_server()
        status, _, err = self.run_sshping("-r", "s", "-s", "1",
                                          "-z", "new.tmp")
        self.assertEqual(status, 0, err)
        self.assertEqual(self.remote_files(), [])

    def test_unwritable_remote_file_fails(self):
        self.start_server()
        status, _, err = self.run_sshping("-r", "s", "-s", "1",
                                          "-z", "/no/such/dir/x.tmp")
        self.assertEqual(status, sshping.EXIT_TEST_FAILED)
        self.assertIn("Upload failed", err)

    def test_echo_stops_when_terminal_buffer_fills(self):
        self.start_server(echo_limit=40)
        status, results, err = self.run_sshping("-r", "e", "-c", "100")
        self.assertEqual(status, 0, err)
        self.assertEqual(results["Echo-Count"], "40 B")
        self.assertIn("echo stopped after 40 characters", err)

    def test_no_echo_at_all_fails(self):
        self.start_server(echo_limit=0)
        status, _, err = self.run_sshping("-r", "e", "-c", "10")
        self.assertEqual(status, sshping.EXIT_TEST_FAILED)
        self.assertIn("No echo", err)

    def test_wrong_password(self):
        self.start_server()
        status, _, err = self.run_sshping(password="wrong")
        self.assertEqual(status, sshping.EXIT_CONNECT_FAILED)
        self.assertIn("Cannot authenticate", err)


class TestShellThatNeverAnswers(FakeServerTestCase):
    server_class = ShellWithoutTerminalServer

    def test_falls_back_to_terminal_echo(self):
        self.start_server()
        status, results, err = self.run_sshping("-c", "50", "-s", "1")
        self.assertEqual(status, 0, err)
        self.assertEqual(results["Echo-Count"], "50 B")
        self.assertEqual(results["Download-Size"], "1000000 B")
        self.assertIn("login shell did not answer", err)
        # The wait for the shell is not part of the login time
        login_ns = int(results["ssh-Login-Time"].split()[0])
        self.assertLess(login_ns, sshping.GIGA * sshping.SHELL_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
