import base64
import os
from conn_manager import ConnectionManager
from tdg_logging import *
from common import *

class WicdManager(ConnectionManager):
    conntype = None
    essid = None
    bssid = None

    def __init__(self):
        ConnectionManager.__init__(self)

    def parse_args(self, pid):
        import argparse
        parser = argparse.ArgumentParser(description=(
            "This script is called before Wicd connects to a network, "
            "in order to rotate Tor's state file, such that state "
            "files used by Tor are always specific to the BSSID of "
            "LAN/WLAN network access point that Wicd is about to "
            "attempt to connect to.%s" %  resume_tor(pid)))
        parser.add_argument('-f', '--config',
                            help='tordyguards config file')
        parser.add_argument('connection_type',
                            help='(wireless, ethernet)')
        parser.add_argument('essid')
        parser.add_argument('bssid')
        args = parser.parse_args()

        self.conntype = args.connection_type
        self.essid = base64.b16encode(args.essid)
        self.bssid = args.bssid

    def get_bssid(self):
        return self.bssid

    def get_essid(self):
        return self.essid

    def get_ebssid(self):
        return self.get_essid(), self.get_bssid()

    def need_devices(self):
        return False

    def should_continue(self, *kargs):
        if not (self.essid or self.bssid):
            logger.info("We have neither essid nor bssid")
            return False
        return True
