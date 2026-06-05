# sshpass-win32

Like https://linux.die.net/man/1/sshpass 

# Pre-Requirements

To run sshpass, you must install:

- Windows 10 Insider build 17733 or later

# Install

## Winget

```sh
winget install xhcoding.sshpass-win32
```

## Scoop

```sh
scoop install sshpass
```

# Usage

```sh
Usage: sshpass [ options ] command arguments

    -h, --help    show this help message and exit
    -V, --version Print version information

Password options: With no options - password will be taken from stdin
    -f=<str>      Take password to use from file
    -d=<int>      Use number as file descriptor for getting password
    -p=<str>      Provide password as argument (security unwise)
    -e            Password is passed as env-var "SSHPASS"

Other options:
    -P=<str>      Which string should sshpass search for to detect a password prompt
    -v            Be verbose about what you're doing
    -k            Auto confirm 'Are you sure...' prompt for host keys
```

# Examples

```sh
sshpass -p 12345 ssh xhcoding@192.168.139.128 ls
```

```sh
sshpass -p 12345 rsync -avz -e 'c:/Users/xhcoding/scoop/apps/cwrsync/current/bin/ssh.exe' README.md xhcoding@192.168.139.128:/home/xhcoding/
```
