import base64
from subprocess import Popen, PIPE, STDOUT
from common import *
from tdg_logging import *
from tdg_rpc_wrappers import *

def hexify_essid(essid):
    if essid[0] == '"':
        essid = essid[1:]
    if essid[-1] == '"':
        essid = essid[:-1]
    return base64.b16encode(essid)

def parse_iwconfig_for_e_b_ssid(iwout, iface):
    # We want ESSID and "Access Point"
    essid = None
    bssid = None
    lines = iwout.split('\n')
    for line in lines:
        words = line.split()
        if not words:
            continue
        if words[0] == iface:
            if words[3].startswith('ESSID:'):
                essid = words[3].split(':')
                if len(essid) != 2:
                    logger.info("Malformed ESSID field: %s" % words[3])
                    continue
                essid = essid[1]
                essid = hexify_essid(essid)
        elif words[0].startswith('Mode:'):
            if len(words) == 6 and words[4] == "Point:":
                bssid = words[5]
    return essid, bssid

def get_e_and_b_ssid(iface, exepath):
    args = [exepath, iface]
    logger.info("Launching %s %s" % (exepath, iface))
    p = Popen(args, stdout=PIPE, stderr=STDOUT)
    p.wait()
    stdout, stderr = p.communicate()
    if not stdout:
        logger.info("%s didn't return anything to stdout or stderr." % exepath)
        return None, None
    return parse_iwconfig_for_e_b_ssid(stdout, iface)

def get_or_prompt_for_ebssid(essid, bssid, statestore_path):
    net_list = get_list_of_known_networks(statestore_path)
    if not net_list:
	logger.info("No known networks")
        return essid, bssid
    elif (essid, bssid) not in net_list:
	logger.debug("Known networks:")
        for e, b in net_list:
            logger.debug("          '%s' - '%s'", e, b)
        if not essid:
            essid = "<unknown>"
        if not bssid:
            bssid = "<unknown>"
    else:
	logger.info("We have a match! Known network %s from %s" % (essid, bssid))

    return essid, bssid

def get_previous_e_and_b_ssids(previous_ebssid):
    previous_ebssid_split = previous_ebssid.split('.')
    previous_essid = previous_bssid = None
    if len(previous_ebssid_split) == 2:
        previous_essid = previous_ebssid_split[0]
        previous_bssid = previous_ebssid_split[1]
    elif len(previous_ebssid_split) == 1:
        # determine if essid or bssid, use it
        indx = previous_ebssid.find('.')
        if indx == 0:
            # .${previous_bssid}
            previous_bssid = previous_ebssid_split[0]
            previous_essid = ''
        elif indx - 1 == len(previous_ebssid):
            # ${previous_essid}.
            previous_essid = previous_ebssid_split[0]
            previous_bssid = ''
        else:
            previous_ebssid = False
    else:
        previous_ebssid = False
    return (previous_ebssid, previous_essid, previous_bssid)

def last_ebssid_file_exists(last_ebssid_fp):
    logger.info("checking if %s exists" % (last_ebssid_fp,))
    if file_exists(last_ebssid_fp):
        previous_ebssid = read_file(last_ebssid_fp)
        logger.info("previous ebssid was %s" % (previous_ebssid,))
        return previous_ebssid
    return False


