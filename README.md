# ssh-copypasta

`ssh-copypasta` is a Python script that manages public SSH
keys on a community server, where keys are added and removed frequently.

After startup, the script continuously monitors a directory that (should)
contain authorized public keys for the server. Whenever the directory changes
its contents, the `authorized_key` file is updated appropriately
(usually `$HOME/.ssh/authorized_keys`).
 
This makes changing authorized public keys easy, because they can each be in
separate files, which are named according to the person they belong to, for
instance.

The scripts also logs all relevant events related to key changes.

## Usage
| usage: `ssh-copypasta.py [-h] [-l LOGFILE] DIRECTORY AUTHORIZED_KEYS`

| positional arguments:  
|   `DIRECTORY`        the directory to be monitored for changes
|   `AUTHORIZED_KEYS`  the file for authorized SSH keys (usually `$HOME/.ssh/authorized_keys`)

| optional arguments:
|   `-h, --help`       show this help message and exit
|   `-l LOGFILE`       specify a logfile. Defaults to `$HOME/ssh-copypasta.log`

## Dependencies
* (Python 3)[https://www.python.org/]
* (pyinotify)[https://pypi.python.org/pypi/pyinotify]
