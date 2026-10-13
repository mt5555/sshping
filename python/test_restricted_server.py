#!/usr/bin/env python3
"""End-to-end tests of sshping.py against fake ssh servers built with
paramiko, mainly one that behaves like a restricted account such as
rsync.net's: no shell, a fixed list of commands run without shell syntax,
and SFTP."""

import contextlib
import io
import os
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


class FakeSFTP(paramiko.SFTPServerInterface):
    """SFTP rooted at the fake server's home directory."""

    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root = server.home

    def _path(self, path):
        return os.path.join(self.root,
                            os.path.normpath("/" + path).lstrip("/"))

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self._path(path)))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    lstat = stat

    def open(self, path, flags, attr):
        try:
            fd = os.open(self._path(path), flags, 0o600)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        writable = flags & (os.O_WRONLY | os.O_RDWR)
        f = os.fdopen(fd, "r+b" if flags & os.O_RDWR else
                      "wb" if writable else "rb")
        handle = paramiko.SFTPHandle(flags)
        if writable:
            handle.writefile = f
        if not flags & os.O_WRONLY:
            handle.readfile = f
        return handle

    def remove(self, path):
        try:
            os.remove(self._path(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK


class RestrictedServer(paramiko.ServerInterface):
    """An rsync.net-style account.  A shell request gets a terminal that
    nothing reads, so only the terminal driver's echo comes back.  Commands
    are split into words with no shell parsing, and only a fixed list is
    allowed (of which this fake implements just echo)."""

    ALLOWED = {"cat", "dd", "echo", "test", "ls", "rm", "mkdir", "touch",
               "stat", "df"}
    shell_quotes = False

    def __init__(self, home, echo_limit=None):
        self.home = home
        self.echo_limit = echo_limit
        self.exec_commands = []
        self.exec_output = []  # words of each command, after it finished

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
        threading.Thread(target=self._run, args=(channel, command),
                         daemon=True).start()
        return True

    def _run(self, chan, command):
        words = shlex.split(command) if self.shell_quotes else command.split()
        name = words[0] if words else ""
        if name == "echo":
            chan.sendall((" ".join(words[1:]) + "\n").encode())
            status = 0
        elif name in self.ALLOWED:
            chan.sendall_stderr(f"fake server: {name} not implemented\n"
                                .encode())
            status = 1
        else:
            chan.sendall_stderr(f"Command not allowed: {name}\n".encode())
            status = 1
        chan.send_exit_status(status)
        # End with EOF rather than close(): closing can beat paramiko's
        # reply to the exec request, which the client sees as a failure
        chan.shutdown_write()
        self.exec_output.append(words)


class ShellWithoutTerminalServer(RestrictedServer):
    """Commands run under a real shell, but an interactive login never
    answers (a menu, or a login that hangs)."""
    shell_quotes = True


class FakeSSHServer:
    """Accepts ssh connections on localhost in a background thread."""

    def __init__(self, server, sftp=True):
        self.server = server
        self.sftp = sftp
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
            if self.sftp:
                t.set_subsystem_handler("sftp", paramiko.SFTPServer, FakeSFTP)
            self.transports.append(t)
            try:
                t.start_server(server=self.server)
            except paramiko.SSHException:
                pass

    def close(self):
        self.sock.close()
        for t in self.transports:
            t.close()


class ShelllessTestCase(unittest.TestCase):
    server_class = RestrictedServer

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = os.path.join(tmp.name, "remote")
        self.local_home = os.path.join(tmp.name, "local")
        os.mkdir(self.home)
        os.mkdir(self.local_home)
        # Keep the waits short so the tests run quickly
        for name, value in (("LOGIN_QUIET", 0.2), ("ECHO_TIMEOUT", 0.5),
                            ("SHELL_TIMEOUT", 1.0)):
            patcher = mock.patch.object(sshping, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def start_server(self, sftp=True, **kwargs):
        self.server = self.server_class(self.home, **kwargs)
        self.ssh = FakeSSHServer(self.server, sftp=sftp)
        self.addCleanup(self.ssh.close)

    def run_sshping(self, *args):
        """Run sshping in-process with no local keys, agent or ssh config.
        Returns (exit status, {label: value} from stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        env = {"HOME": self.local_home, "SSH_AUTH_SOCK": ""}
        with mock.patch.dict(os.environ, env), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            status = sshping.main([*args, "-p", PASSWORD,
                                   f"{USER}@127.0.0.1:{self.ssh.port}"])
        results = {}
        for line in out.getvalue().splitlines():
            label, sep, value = line.partition(":")
            if sep:
                results[label] = value.strip()
        return status, results, err.getvalue()


class TestRestrictedAccount(ShelllessTestCase):

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
        self.assertIn("the speed test uses SFTP", err)
        # The only command run is the shell check, and the temporary file
        # is gone afterwards
        self.assertEqual(self.server.exec_commands, ['echo SSHPING_""READY'])
        self.assertEqual(self.server.exec_output,
                         [["echo", 'SSHPING_""READY']])
        self.assertEqual(os.listdir(self.home), [])

    def test_existing_remote_file_is_kept(self):
        self.start_server()
        path = os.path.join(self.home, "existing.tmp")
        with open(path, "w") as f:
            f.write("old")
        status, results, err = self.run_sshping("-r", "s", "-s", "1",
                                                "-z", "existing.tmp")
        self.assertEqual(status, 0, err)
        self.assertEqual(os.path.getsize(path), sshping.MEGA)

    def test_new_remote_file_is_removed(self):
        self.start_server()
        status, _, err = self.run_sshping("-r", "s", "-s", "1",
                                          "-z", "new.tmp")
        self.assertEqual(status, 0, err)
        self.assertEqual(os.listdir(self.home), [])

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

    def test_without_sftp_the_speed_test_fails(self):
        self.start_server(sftp=False)
        status, results, err = self.run_sshping("-c", "20", "-s", "1")
        self.assertEqual(status, sshping.EXIT_TEST_FAILED)
        self.assertEqual(results["Echo-Count"], "20 B")
        self.assertIn("Cannot start SFTP", err)

    def test_wrong_password(self):
        self.start_server()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": self.local_home,
                                          "SSH_AUTH_SOCK": ""}), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            status = sshping.main(["-p", "wrong",
                                   f"{USER}@127.0.0.1:{self.ssh.port}"])
        self.assertEqual(status, sshping.EXIT_CONNECT_FAILED)
        self.assertIn("Cannot authenticate", err.getvalue())


class TestShellThatNeverAnswers(ShelllessTestCase):
    server_class = ShellWithoutTerminalServer

    def test_falls_back_to_terminal_echo(self):
        self.start_server()
        status, results, err = self.run_sshping("-r", "e", "-c", "50")
        self.assertEqual(status, 0, err)
        self.assertEqual(results["Echo-Count"], "50 B")
        self.assertIn("login shell did not answer", err)
        # The wait for the shell is not part of the login time
        login_ns = int(results["ssh-Login-Time"].split()[0])
        self.assertLess(login_ns, sshping.GIGA * sshping.SHELL_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
