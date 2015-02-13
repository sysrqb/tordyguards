import os
from conn_manager import ConnectionManager
from tdg_logging import *
from common import *

class NMManager(ConnectionManager):
    interface = None
    interface_ = None
    status = None
    status_ = None
    connuuid = None
    wireless_devs = list()
    all_devs = list()

    def __init__(self):
        ConnectionManager.__init__(self)

        try:
            self.connuuid = os.environ['CONNECTION_UUID']
            logger.info("CONNECTION_UUID = %s.", self.connuuid)
        except:
            pass

    def parse_args(self, pid):
        import argparse
        parser = argparse.ArgumentParser(description=(
            "This script is called after NetworkManager connects to a "
            "network, the script then rotates Tor's state file, such "
            "that state files used by Tor are always specific to the "
            "ESSID/BSSID of LAN/WLAN network access point that to "
            "which NetworkManager connected.%s" % resume_tor(pid)))
        parser.add_argument('-f', '--config',
                            help='tordyguards config file')
        parser.add_argument('interface')
        parser.add_argument('status')
        args = parser.parse_args()

        self.interface_ = args.interface
        self.status_ = args.status
        logger.info("Called with: '%s' '%s'" % (args.interface, args.status))

    def get_bssid(self):
        pass
    def get_essid(self):
        pass
    def get_ebssid(self):
        essid = None
        bssid = None
        logger.info("Confirming %s is a device in %s.",
                    self.interface, self.wireless_devs)
        if self.interface in self.wireless_devs:
            logger.info("Searching for iwconfig")
            have_iwconfig = get_iwconfig()
            logger.info("%s is wireless and we found it: %s",
                        self.interface, have_iwconfig)
            if not have_iwconfig:
                logger.info("Can't find iwconfig. Failing.")
                return (None, None)
            essid, bssid = get_e_and_b_ssid(self.interface, have_iwconfig)
            if None in (essid, bssid):
                logger.info("Couldn't get essid (%s) or bssid (%s) . Failing." % \
                            (essid, bssid,))
        #else:
            # We must ask for a unique name
            #pass
        logger.info("ESSID: %s, BSSID: %s.", essid, bssid)
        return essid, bssid

    def need_devices(self):
        return True

    def set_devices(self, (wireless, alldevs)):
        self.wireless_devs = wireless
        self.all_devs = alldevs

    def should_continue(self, *kargs):
        if not self.interface_:
            return False
        self.interface = get_first_word(self.interface_)
        # it shouldn't be more than 16(?) chars, but 8 should be
        # more than enough for what we need
        self.interface = self.interface[:8]
        # We only care about 'up' state
        self.status = self.status_[:2]

        # Don't try if we're working with the loopback or the
        # interface isn't up
        if self.interface and self.interface == 'lo':
            logger.info("Called with interface lo. Done.")
            return False
        if self.status and self.status != 'up':
            logger.info("Called with interface %s and status '%s'. Done." % \
                        (self.interface_, self.status_,))
            return False
        if self.interface not in self.all_devs and self.status:
            logger.info("Called with unknown interface '%s' and status '%s'. Failing." % \
                        (self.interface_, self.status_,))
            return False
        return True

