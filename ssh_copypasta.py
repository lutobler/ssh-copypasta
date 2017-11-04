#!/usr/bin/env python3

# depends on: pyinotify

import argparse
import pyinotify
import sys
import os
import re
import datetime
from typing import Tuple

def log(msg: str) -> None:
    with open(log_file, 'a') as fd:
        time_str = '[' + datetime.datetime.now().isoformat() + '] '
        fd.write(time_str + msg + '\n')


# Check if file given by `keyfile_name` contains a public key and return it if it does.
def is_pub_key(keyfile_name: str) -> Tuple[bool, str]:
    pkey_regex = re.compile('^.*\.pub$')
    if not pkey_regex.match(keyfile_name):
        print("no match")
        return False, None

    with open(keyfile_name, 'r') as fd:
        content = fd.read()

    ssh_key_regex = re.compile('^ssh-rsa .*')
    if not ssh_key_regex.match(content):
        print("no match2")
        return False, None

    return True, content

def build_authorized_keys_file() -> None:
    with open(auth_keys, 'w+') as fd:
        for f in os.listdir(watch_dir):
            file_path = watch_dir + '/' + f
            success, key = is_pub_key(file_path)
            if success:
                fd.write('\n' + key + '\n')

def add_key(path: str, name: str) -> None:
    file_name = path + '/' + name
    b,_ = is_pub_key(file_name)
    if not b:
        log('Key file has invalid format: ' + file_name)
        return

    log('New public key: `' + name + '`, regenerating authorized_keys')
    build_authorized_keys_file()

def remove_key(path: str, name: str) -> None:
    file_name = path + '/' + name
    log('Removed file: `' + file_name + '`, regenerating authorized_keys')
    build_authorized_keys_file()

# Watcher class that executes appropriate functions whenever files are added/removed from the watch directory
class OnCreateDeleteHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event: pyinotify.Event) -> None:
        add_key(event.path, event.name)

    def process_IN_DELETE(self, event: pyinotify.Event) -> None:
        remove_key(event.path, event.name)


if __name__ == '__main__':
    # default log file is in home directory
    log_file = os.getenv('HOME') + '/ssh-copypasta.log'

    # argument parsing setup
    parser = argparse.ArgumentParser()
    parser.add_argument('DIRECTORY', metavar='DIRECTORY',
            help='the directory to be monitored for changes')
    parser.add_argument('AUTHORIZED_KEYS', metavar='AUTHORIZED_KEYS',
            help='the file for authorized SSH keys (usually $HOME/.ssh/authorized_keys)')
    parser.add_argument('-l', metavar='LOGFILE',
            help='specify a logfile. Defaults to $HOME/ssh-copypasta.log')

    # parse and check arguments
    args = parser.parse_args()
    watch_dir = args.DIRECTORY
    auth_keys = args.AUTHORIZED_KEYS
    log_file = args.l

    # check if watch directory exists
    if not os.path.exists(watch_dir):
        sys.stderr.write('specified watch directory does not exist\n')
        sys.exit(1)

    # create log file if it doesn't exist
    if not os.path.isfile(log_file):
        open(log_file, 'w').close()

    # create auth_keys file if it doesn't exist
    if not os.path.isfile(auth_keys):
        open(auth_keys, 'w').close()

    # setup inotify and enter notification loop
    wm = pyinotify.WatchManager()
    event_handler = OnCreateDeleteHandler()
    notifier = pyinotify.Notifier(wm, default_proc_fun=event_handler)
    INOTIFY_MASK = pyinotify.IN_DELETE | pyinotify.IN_CREATE
    wm.add_watch(watch_dir, INOTIFY_MASK, rec=True, auto_add=True)
    notifier.loop()

