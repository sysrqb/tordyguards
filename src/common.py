import base64
import os
import shutil
import signal
from subprocess import Popen, PIPE, STDOUT
from tdg_logging import *

def init_devices_lists():
    wireless_file = "/proc/net/wireless"
    all_file = "/proc/net/dev"
    wireless_dev = None
    all_dev = None

    for devfile in [wireless_file, all_file]:
        if os.path.exists(devfile):
            with open(devfile) as f:
                dev_list = list()
                iface = None
                for line in f:
                    if line.startswith("Inter-"):
                        continue
                    if line.startswith(" face"):
                        continue
                    words = line.split()
                    if len(words) < 1:
                        continue
                    iface = words[0]
                    if iface[-1] == ':':
                        iface = iface[:-1]
                    dev_list.append(iface)
                    iface = None
            if devfile == wireless_file:
                wireless_dev = dev_list
            elif devfile == all_file:
                all_dev = dev_list
        else:
            logger.warn("%s: not found." % devfile)
    return wireless_dev, all_dev

def create_state_store(path):
    try:
        os.mkdir(path, 0600)
    except OSError:
        # Exception thrown when dir exists, too
        pass
    return os.path.isdir(path)

def last_ebssid_full_path(state_path, last_ebssid_fn):
    return os.path.join(state_path, last_ebssid_fn)


def state_full_path(state_path, state_fn):
    return os.path.join(state_path, state_fn)


def state_ebssid_full_path(state_path, essid, bssid):
    ebssid_file = essid + "." + bssid.replace(":", "_")
    return os.path.join(state_path, ebssid_file)


def state_old_full_path(state_path, state_fn):
    return os.path.join(state_path, state_fn + ".old")


def file_exists(state_full_path):
    logger.info("checking if %s exists" % (state_full_path,))
    return os.path.isfile(state_full_path)


def last_ebssid_file_exists(last_ebssid_fp):
    logger.info("checking if %s exists" % (last_ebssid_fp,))
    if os.path.isfile(last_ebssid_fp):
        previous_ebssid = read_file(last_ebssid_fp)
        logger.info("previous ebssid was %s" % (previous_ebssid,))
        return previous_ebssid
    return False

def get_list_of_known_networks(path):
    if not os.path.isdir(path):
        logger.info("StateStore not a directory")
        return list()
    networks = list()
    for f in os.listdir(path):
        if f in ("last_ebssid", "state.old"):
            continue
        logger.info("Found %s in StateStore." % f)
        parts = f.split('.')
        if len(parts) != 2:
            continue
        logger.info("Found: essid = %s, bssid = %s." % (parts[0], parts[1]))
        essid = parts[0]
        bssid = parts[1].replace('_', ':')
        networks.append((essid, bssid))
    return networks

def mv_file(from_file, to_file):
    # os.system("mv %s %s" % (from_file, to_file))
    shutil.move(from_file, to_file) # Me
    logger.info("mv %s %s" % (from_file, to_file))

def cp_file(from_file, to_file):
    # when copying state.bssid to state, use tor user
    #os.system("sudo -u %s -H cp %s %s" % (TOR_USER, from_file, to_file))
    #shutil.copy2(from_file, to_file)
    p = Popen(['cp', '-p', '--preserve', from_file, to_file]) # Me
    p.wait() # Me
    logger.info("cp %s %s" % (from_file, to_file))


def update_last_ebssid_file(last_ebssid_fp, ebssid):
    """Update the file where the last wireless bssid is stored

    :param ebssid: ebssid
    :type ebssid: string
    :param last_ebssid_fp: full path where the last ebssid is stored
    :type last_ebssid_fp: string
    """

    fd = open(last_ebssid_fp, 'w')
    fd.write(ebssid)
    fd.close()
    logger.info("updated %s with ebssid %s" % (last_ebssid_fp, ebssid))

def get_first_word(line):
    if not line:
        return None 
    words = line.split()
    return words[0]

def get_iwconfig():
    try:
        path = os.environ['PATH']
    except KeyError:
        logger.info("No PATH set. Using default root path.")
        path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    if not path:
        logger.info("No PATH set. Failing.")
        return False
    pathlist = path.split(':')
    if len(pathlist) < 1:
        logger.info("PATH empty. Failing.")
        return False
    for d in pathlist:
        iwpath = os.path.join(d, 'iwconfig')
        logger.info('Looking for %s' % iwpath)
        if os.path.isfile(iwpath):
            logger.info('Found %s' % iwpath)
            return iwpath
    return False

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

def stop_tor_process(stop_tor):
    logger.info("stopping tor") 
    os.system(stop_tor) 

def start_tor_process(start_tor):
    logger.info("starting tor")
    os.system(start_tor)

def suspend_tor(pid):
    logger.info("suspending tor")
    os.kill(pid, signal.SIGSTOP)

def resume_tor(pid):
    logger.info("resuming tor")
    os.kill(pid, signal.SIGCONT)

def read_file(fn):
    content = None
    try:
        with open(fn) as fd:
            content = fd.read().strip()
    except IOError as e:
        logger.warn("Failed while opening '%s': %s", fn, e)
        return False
    return content
