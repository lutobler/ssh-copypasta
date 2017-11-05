import argparse
import pyinotify
import sys
import os
import re
import datetime
from typing import Tuple


def is_pub_key(keyfile_name: str) -> Tuple[bool, str]:
    """
    Check if a file is a valid key file and perform rudimentary sanity-check.
    If it is valid, also return the files' content.
    """
    pkey_regex = re.compile('^.*\.pub$')
    if not pkey_regex.match(keyfile_name):
        return False, None

    with open(keyfile_name, 'r') as fd:
        content = fd.read()

    ssh_key_regex = re.compile('^ssh-rsa .*')
    if not ssh_key_regex.match(content):
        return False, None

    return True, content


class OnCreateDeleteHandler(pyinotify.ProcessEvent):
    """
    Implementation of pyinotify.ProcessEvent that handles file being
    added/removed from the watch directory.
    """

    def __init__(self, auth_keys: str, watch_dir: str, log_file: str) -> None:
        self.auth_keys = auth_keys
        self.watch_dir = watch_dir
        self.log_file = log_file

    def log(self, msg: str) -> None:
        """Log a message to the log file, with an added timestamp."""
        if not self.log_file:
            return
        with open(self.log_file, 'a') as fd:
            time_str = '[' + datetime.datetime.now().isoformat() + '] '
            fd.write(time_str + msg + '\n')

    def process_IN_CREATE(self, event: pyinotify.Event) -> None:
        """Event handler for created files."""
        self.add_key(event.path, event.name)

    def process_IN_DELETE(self, event: pyinotify.Event) -> None:
        """Event handler for deleted files."""
        self.remove_key(event.path, event.name)

    def build_authorized_keys_file(self) -> None:
        """Build the authorized_keys file from scratch and write it out."""
        with open(self.auth_keys, 'w+') as fd:
            for f in os.listdir(self.watch_dir):
                file_path = self.watch_dir + '/' + f
                success, key = is_pub_key(file_path)
                if success:
                    fd.write('\n' + key + '\n')

    def add_key(self, path: str, name: str) -> None:
        """Update authorized_keys file when a key is added."""
        file_name = path + '/' + name
        b,_ = is_pub_key(file_name)
        if not b:
            self.log('Key file has invalid format: ' + file_name)
            return

        self.log('New public key: `' + name
                 + '`, regenerating authorized_keys')
        self.build_authorized_keys_file()

    def remove_key(self, path: str, name: str) -> None:
        """Update authorized_keys file when a key is deleted."""
        file_name = path + '/' + name
        self.log('Removed file: `' + file_name
                 + '`, regenerating authorized_keys')
        self.build_authorized_keys_file()


def build_notifier(auth_keys: str, watch_dir: str,
                  log_file: str) -> pyinotify.ThreadedNotifier:
    """Setup pyinotify and return a notifier object"""

    wm = pyinotify.WatchManager()
    event_handler = OnCreateDeleteHandler(auth_keys, watch_dir, log_file)
    notifier = pyinotify.ThreadedNotifier(wm,
                                          default_proc_fun=event_handler)
    INOTIFY_MASK = pyinotify.IN_DELETE | pyinotify.IN_CREATE
    wm.add_watch(watch_dir, INOTIFY_MASK, rec=True, auto_add=True)
    return notifier


if __name__ == '__main__':
    # default log file is in home directory
    log_file = os.getenv('HOME') + '/ssh-copypasta.log'

    # argument parsing setup
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'DIRECTORY',
        metavar='DIRECTORY',
        help='the directory to be monitored for changes'
    )
    parser.add_argument(
        'AUTHORIZED_KEYS',
        metavar='AUTHORIZED_KEYS',
        help='the file for authorized SSH keys'
             + ' (usually $HOME/.ssh/authorized_keys)'
    )
    parser.add_argument(
        '-l',
        metavar='LOGFILE',
        help='specify a logfile. default: $HOME/ssh-copypasta.log'
    )

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

    notifier = build_notifier(auth_keys, watch_dir, log_file)
    notifier.start()

