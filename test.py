#!/usr/bin/env python3

import unittest
import threading
import os
import shutil
from ssh_copypasta import *

class TestKeyRegexes(unittest.TestCase):
    def test_pubkey_regex(self):
        self.assertEqual((False, None), is_pub_key('test/empty.pub'))
        self.assertEqual((False, None), is_pub_key('test/garbage_pub.notpub'))
        pubkey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+pD0/oRNRxeaa+AsXeomSGROKmDv42MspJQRtVDQlC7MvmpYwwtWL+wUKWfSevINp9YCiiFt1iKSJkaAepf2hsXfXBQh3F5hlYV0UwhNKbUu+7670G3BNsoXDTcAYjK5slNyQFzXlyW9zFmNCb0LFODUHRDF374Yi+4/NtvmqeZAI2rjLYBSE8omm1WctEzG29in5VHfSsVQE9j3/ExGn1EoZLpjeMRA1x2b+MPgjnWxYlBJrIT4yjfo2uMhZJ8P+SB87KNhGwVJJcho9pwSKbo0sQTHn6a46ki1pjQzWKi+NDc6NTNcxxM+5hLsq1Q+thKRvkMph8CKdlC8Li8Jp nils@Velociraptor\n'
        self.assertEqual((True, pubkey), is_pub_key('test/realkey.pub'))

class TestKeyUpdating(unittest.TestCase):
    # Directory the public keys for testing reside in
    KEYS_DIR = 'test/testkeys/keys/'

    def setUp(self):
        self.auth_keys = 'test/testkeys/auth_keys'
        self.watch_dir = 'test/testkeys/watch_dir/'
        self.log_file = 'test/testkeys/log'

        for f in os.listdir(self.watch_dir):
            os.remove(self.watch_dir + f)

        # Empty logfile
        with open(self.log_file, 'w') as f:
            f.write("\n")

        # Empty auth_keys
        with open(self.auth_keys, 'w') as f:
            f.write("")

        self.notifier = OnCreateDeleteHandler.setup_watcher(self.auth_keys, 
                self.watch_dir, self.log_file)
        self.notifier.start()

    # Do some additions and deletions of keys
    def test_auth_keys_generation(self):
        # Copy all keys into the watch_dir. The notifier will watch all events
        files = os.listdir(TestKeyUpdating.KEYS_DIR)
        for f in files:
            shutil.copy(TestKeyUpdating.KEYS_DIR + f, self.watch_dir)
            
            
        # FIXME: os.sync() might not be enough here. We definitely need a delay
        # or a barrier before doing the asserts. I'm not sure wheter os.sync()
        # is the barrier or the delay in this case. Maybe it's both.
        os.sync()
        self.notifier.stop()

        # auth_keys file should contain keys surrounded by an empty line 
        self.assertEqual(len(files) * 3, sum(1 for line in  open(self.auth_keys)))

        # Logfile should contain an entry for every key added
        self.assertEqual(len(files) + 1, sum(1 for line in open(self.log_file)))

        # Threads can only be started once, so need to get new notifier.
        self.notifier = OnCreateDeleteHandler.setup_watcher(self.auth_keys, 
                self.watch_dir, self.log_file)
        self.notifier.start()
        for f in files:
            os.remove(self.watch_dir + f)

        # FIXME: os.sync() might not be enough here. We definitely need a delay
        # or a barrier before doing the asserts. I'm not sure wheter os.sync()
        # is the barrier or the delay in this case. Maybe it's both.
        os.sync()
        self.notifier.stop()
        # auth_keys should be empty
        self.assertEqual(0, sum(1 for line in open(self.auth_keys)))

        # Logfile should contain an entry for every key added and removed
        self.assertEqual(len(files) * 2, sum(1 for line in open(self.log_file)) - 1)

def regex_test_suite():
    return unittest.TestLoader().loadTestsFromTestCase(TestKeyRegexes)

def key_update_test_suite():
    return unittest.TestLoader().loadTestsFromTestCase(TestKeyUpdating)

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(regex_test_suite())
    runner.run(key_update_test_suite())

