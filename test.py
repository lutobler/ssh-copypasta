#!/usr/bin/env python3

import unittest
from ssh_copypasta import *

class TestKeyRegexes(unittest.TestCase):

    def test_pubkey_regex(self):
        self.assertEqual((False, None), is_pub_key('test/empty.pub'))
        self.assertEqual((False, None), is_pub_key('test/garbage_pub.notpub'))
        pubkey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+pD0/oRNRxeaa+AsXeomSGROKmDv42MspJQRtVDQlC7MvmpYwwtWL+wUKWfSevINp9YCiiFt1iKSJkaAepf2hsXfXBQh3F5hlYV0UwhNKbUu+7670G3BNsoXDTcAYjK5slNyQFzXlyW9zFmNCb0LFODUHRDF374Yi+4/NtvmqeZAI2rjLYBSE8omm1WctEzG29in5VHfSsVQE9j3/ExGn1EoZLpjeMRA1x2b+MPgjnWxYlBJrIT4yjfo2uMhZJ8P+SB87KNhGwVJJcho9pwSKbo0sQTHn6a46ki1pjQzWKi+NDc6NTNcxxM+5hLsq1Q+thKRvkMph8CKdlC8Li8Jp nils@Velociraptor'
        self.assertEqual((True, pubkey), is_pub_key('test/realkey.pub'))

if __name__ == '__main__':
    unittest.main()

