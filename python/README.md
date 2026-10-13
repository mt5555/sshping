# sshping (Python)

A Python port of sshping. It measures the character-echo latency of an
interactive ssh session, plus upload and download throughput. It needs no
compiler and runs anywhere Python 3.8+ and
[paramiko](https://www.paramiko.org/) run.

    pip install -r requirements.txt
    ./sshping.py [options] [user@]addr[:port]

Run `./sshping.py --help` for all options. Most options match the C++ version.

## What is measured

`ssh-Login-Time` is the time from opening the TCP connection until the
remote login shell answers a command. Time spent typing passwords or
passphrases is not counted.

In the echo test, sshping sends one character at a time, waits for it to come
back, and records the round-trip time. By default the remote echo command is
`stty raw -echo; cat`, so a remote *process* echoes each character, the way a
shell or editor does. The measured latency therefore includes waking up a
process on the server, which on a busy login node can be a large part of what
you feel as lag. To measure only the network, sshd and the remote kernel's
terminal driver (the C++ version's default), use:

    ./sshping.py -e 'cat > /dev/null' host

The speed test streams `-s` megabytes to a remote file and then reads them
back, one ssh channel each way. By default the file is a new `mktemp` file in
`/tmp`, removed afterwards. With `-z FILE` it is removed only if it did not
exist before.

Results go to stdout as `Label: value unit` lines. Progress, warnings and
`-v` messages go to stderr. The exit status is 0 on success, 1 if a test
failed, 2 for usage errors and 255 if the connection or login failed.

## Accounts without a shell

Some hosts, such as rsync.net, give an account no shell: it may run only
single commands from a fixed list, plus scp, SFTP and rsync. sshping checks
for this by running `echo SSHPING_""READY`, since only a real shell removes
the quotes. Without a shell it prints a warning and works like the C++
version:

- `ssh-Login-Time` ends when the terminal session's login output stops,
  rather than when a shell answers.
- The echo test sends characters to a terminal session where nothing reads
  them, so the remote terminal driver echoes them. `-e` is ignored. If the
  terminal's input buffer fills, the test stops early with a warning and
  reports what it measured; use `-c` to send fewer characters.
- The speed test uses SFTP, with a randomly named file in the SFTP home
  directory, removed afterwards. A `-z FILE` is removed only if it did not
  exist before. paramiko's SFTP downloads
  more slowly than the `cat` stream used on normal hosts, so compare speed
  results only between hosts tested the same way.

The same fallback applies on a normal host whose interactive login never
answers within 30 s, but there the speed test still uses `cat`.

## Differences from the C++ version

- Process echo is the default (see above).
- The login time no longer includes a fixed 1.3 s wait for login output to stop.
- The server's host key is checked against `~/.ssh/known_hosts` and
  `/etc/ssh/ssh_known_hosts`. A changed key is an error. An unknown key is a
  warning, or an error with `--strict-host-key`.
- `~/.ssh/config` is read for HostName, Port, User, IdentityFile and
  ProxyCommand (`-F` selects another file). ProxyJump is not supported.
- Encrypted private keys prompt for their passphrase.
- `Std-Deviation` replaces `Average-Deviation`, which was always the sample
  standard deviation.
- Fixed C++ bugs: the median of an even number of samples, the mostly
  uninitialized upload buffer, overflow for `-s` above 2147, download byte
  counting, the exit status ignoring test failures, and the leftover remote
  file.
- Commands typed into the remote shell start with a space, so shells set
  to ignore such lines (bash `HISTCONTROL=ignorespace`, the default on
  Debian/Ubuntu) keep them out of the history.

## Accuracy

paramiko adds roughly 0.1 ms per echo compared with the C++ version (median
0.25 ms vs 0.15 ms against a server on localhost). That is small next to
the latency of a real network link, but it makes the Python version a poor
choice for comparing sub-millisecond LAN links. paramiko's bulk transfer is
also slower than OpenSSH or libssh, so on fast links the speed test may
measure paramiko rather than the network.

## Tests

    python3 -m unittest -v

`test_sshping.py` covers formatting, statistics and option parsing.
`test_restricted_server.py` runs sshping end to end against fake ssh
servers built with paramiko, including one that behaves like a restricted
account (no shell, fixed command list, SFTP).
