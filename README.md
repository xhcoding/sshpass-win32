# sshpass-win32

Like https://linux.die.net/man/1/sshpass 

# Pre-Requirements

To run sshpass, you must install:

- Windows 10 Insider build 17733 or later

# Usage

```sh
Usage: sshpass [ options ] command

    -h, --help    show this help message and exit

Password options: With no options - password will be taken from stdin
    -f=<str>      Take password to use from file
    -d=<int>      Use number as file descriptor for getting password
    -p=<str>      Provide password as argument (security unwise)
    -e            Password is passed as env-var "SSHPASS"

Other options:
    -P=<str>      Which string should sshpass search for to detect a password prompt
    -v            Be verbose about what you're doing
```

# Examples

```sh
sshpass.exe -p 12345 "ssh xhcoding@192.168.139.128 ls"
```
