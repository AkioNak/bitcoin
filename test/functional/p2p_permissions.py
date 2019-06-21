#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test p2p permission message.

Test that permissions are correctly calculated and applied
"""

from test_framework.test_node import ErrorMatch
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
)

class P2PPermissionsTests(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[],[]]

    def run_test(self):
        self.checkpermission(
        # relay permission added
        ["-whitelist=127.0.0.1", "-whitelistrelay"],
        ["relay", "noban", "mempool"],
        True)

        self.checkpermission(
        # forcerelay permission added
        ["-whitelist=127.0.0.1", "-whitelistforcerelay"],
        ["forcerelay", "noban", "mempool"],
        True)

        self.checkpermission(
        # legacy whitelistrelay should be ignored
        ["-whitelist=noban,mempool@127.0.0.1", "-whitelistrelay"],
        ["noban", "mempool"],
        True)

        self.checkpermission(
        # legacy whitelistforcerelay should be ignored
        ["-whitelist=noban,mempool@127.0.0.1", "-whitelistforcerelay"],
        ["noban", "mempool"],
        True)

        self.checkpermission(
        # missing mempool permission to be considered legacy whitelisted
        ["-whitelist=noban@127.0.0.1"],
        ["noban"],
        False)

        self.checkpermission(
        # all permission added
        ["-whitelist=all@127.0.0.1"],
        ["forcerelay", "noban", "mempool", "bloomfilter", "relay"],
        True)

        self.nodes[1].stop()
        self.nodes[1].assert_start_raises_init_error(["-whitelist=oopsie@127.0.0.1"], "Invalid P2P permission", match=ErrorMatch.PARTIAL_REGEX)
        self.nodes[1].assert_start_raises_init_error(["-whitelist=noban@127.0.0.1:230"], "Invalid netmask specified in", match=ErrorMatch.PARTIAL_REGEX)
        self.nodes[1].assert_start_raises_init_error(["-whitebind=noban@127.0.0.1/10"], "Cannot resolve -whitebind address", match=ErrorMatch.PARTIAL_REGEX)

    def checkpermission(self, args, expectedPermissions, whitelisted):
        self.restart_node(1, args)
        connect_nodes(self.nodes[0], 1)
        peerinfo = self.nodes[1].getpeerinfo()[0]
        assert_equal(peerinfo['whitelisted'], whitelisted)
        for p in expectedPermissions:
            if not p in peerinfo['permissions']:
                raise AssertionError("Expected permissions %r is not granted." % p)

if __name__ == '__main__':
    P2PPermissionsTests().main()
