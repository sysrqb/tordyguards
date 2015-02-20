try:
    import configparser
except:
    import ConfigParser as configparser
import os
import pwd
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

def create_state_store_(path):
    try:
        os.mkdir(path, 0600)
    except OSError as e:
        # Exception thrown when dir exists, too
        if not os.path.isdir(path):
            raise e
    return os.path.isdir(path)

def rpc_create_state_store(path):
    error = False
    errstr = None
    errno = 0
    res = False
    try:
        res = create_state_store_(path)
    except (IOError, OSError) as e:
        error = True
        errstr = "%s: '%s'" % (e.strerror, e.filename)
        errno = e.errno
    if res:
        return False, res, None
    return error, errno, errstr

def last_ebssid_full_path(state_path, last_ebssid_fn):
    return os.path.join(state_path, last_ebssid_fn)


def state_full_path(state_path, state_fn):
    return os.path.join(state_path, state_fn)


def state_ebssid_full_path(state_path, essid, bssid):
    ebssid_file = essid + "." + bssid.replace(":", "_")
    return os.path.join(state_path, ebssid_file)


def state_old_full_path(state_path, state_fn):
    return os.path.join(state_path, state_fn + ".old")


def file_exists_(state_full_path):
    logger.info("checking if %s exists" % (state_full_path,))
    return os.path.isfile(state_full_path)

def rpc_file_exists(state_full_path):
    res = file_exists_(state_full_path)
    return False, res, None

def dir_exists_(dirpath):
    logger.info("checking if %s exists" % (dirpath,))
    return os.path.isdir(dirpath)

def rpc_dir_exists(dirpath):
    res = dir_exists_(dirpath)
    return False, res, None

def get_list_of_known_networks_(path):
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

def rpc_get_list_of_known_networks(path):
    error = False
    errstr = None
    errno = 0
    res = False
    try:
        res = get_list_of_known_networks_(path)
    except (IOError, OSError) as e:
        error = True
        errstr = "%s: '%s'" % (e.strerror, e.filename)
        errno = e.errno
    if res:
        return False, res, None
    return error, errno, errstr

def mv_file_(from_file, to_file):
    # os.system("mv %s %s" % (from_file, to_file))
    shutil.move(from_file, to_file)
    logger.info("mv %s %s" % (from_file, to_file))

def rpc_mv_file(from_file, to_file):
    error = False
    errstr = None
    errno = 0
    res = False
    try:
        mv_file_(from_file, to_file)
    except (IOError, OSError) as e:
        error = True
        errstr = "%s: '%s'" % (e.strerror, e.filename)
        errno = e.errno
    if res:
        return False, True, None
    return error, errno, errstr

def cp_file_(from_file, to_file):
    #TODO Figure out what is going on here
    # when copying state.bssid to state, use tor user
    #os.system("sudo -u %s -H cp %s %s" % (TOR_USER, from_file, to_file))
    #shutil.copy2(from_file, to_file)
    p = Popen(['cp', '-p', '--preserve', from_file, to_file])
    p.wait() # Me
    logger.info("cp %s %s" % (from_file, to_file))

def rpc_cp_file(from_file, to_file):
    #TODO Error handling
    cp_file_(from_file, to_file)
    return False, True, None

def update_last_ebssid_file_(last_ebssid_fp, ebssid):
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

def rpc_update_last_ebssid_file(last_ebssid_fp, ebssid):
    error = False
    errstr = None
    errno = 0
    res = False
    try:
        update_last_ebssid_file_(last_ebssid_fp, ebssid)
    except (IOError, OSError) as e:
        error = True
        errstr = "%s: '%s'" % (e.strerror, e.filename)
        errno = e.errno
    if res:
        return False, True, None
    return error, errno, errstr

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
    if '/sbin' not in pathlist:
        pathlist.extend(['/usr/local/sbin', '/usr/sbin', '/sbin'])
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

def stop_tor_process_(stop_tor):
    logger.info("stopping tor")
    return os.system(stop_tor)

def rpc_stop_tor_process(stop_tor):
    res = stop_tor_process_(stop_tor)
    if res == 0:
        return False, True, None
    return True, res, "Execution failed"

def start_tor_process_(start_tor):
    logger.info("starting tor")
    return os.system(start_tor)

def rpc_start_tor_process(start_tor):
    res = start_tor_process_(start_tor)
    if res == 0:
        return False, True, None
    return True, res, "Execution failed"

def suspend_tor_(pid):
    if pid == -1:
        return
    logger.info("suspending tor (%d)", pid)
    os.kill(pid, signal.SIGSTOP)

def rpc_suspend_tor(pid):
    error = False
    errstr = None
    errno = 0
    res = False
    try:
        suspend_tor_(pid)
    except OSError as e:
        error = True
        errstr = "%s" % e.strerror
        errno = e.errno
    if res:
        return False, True, None
    return error, errno, errstr

def resume_tor_(pid):
    if pid == -1:
        return
    logger.info("resuming tor (%d)", pid)
    os.kill(pid, signal.SIGCONT)

def rpc_resume_tor(pid):
    error = False
    errstr = None
    errno = 0
    res = False
    try:
        resume_tor_(pid)
    except OSError as e:
        error = True
        errstr = "%s" % e.strerror
        errno = e.errno
    if res:
        return False, True, None
    return error, errno, errstr

def read_file_(fn):
    content = None
    try:
        with open(fn) as fd:
            content = fd.read().strip()
    except IOError as e:
        logger.warn("Failed while opening '%s': %s", fn, e)
        return False
    return content

def rpc_read_file(fn):
    error = False
    errstr = None
    errno = 0
    res = False
    try:
        res = read_file_(fn)
    except OSError as e:
        error = True
        errstr = "%s" % e.strerror
        errno = e.errno
    if res:
        return False, res, None
    return error, errno, errstr

def get_any_config_option(config, section, option, fatal):
    return get_config_option(config, config.get, section, option, fatal)

def get_bool_config_option(config, section, option, fatal):
    return get_config_option(config, config.getboolean, section, option, fatal)

def get_config_option(config, opttype, section, option, fatal):
    value = None
    try:
        value = opttype(section, option)
    except configparser.NoSectionError as e:
        msg = "Could not find section '%s' in config. Looking for " \
              "'%s' in it." % (section, option)
        if fatal:
            logger.warn("%s This is a fatal error. Please correct.",
                         msg)
        else:
            logger.info("%s", msg)
    except configparser.NoOptionError as e:
        msg = "Could not find '%s' in section '%s'." % (option, section)
        if fatal:
            logger.warn("%s This is a fatal error. Please correct.",
                         msg)
        else:
            logger.info("%s", msg)
    return value

def should_switch_user(config):
    limited_user = None
    can_drop_privs = False

    # TODO uid is a bad indicator, we should check better
    if os.getuid() != 0:
        logger.warn("This script must be run as root (or with the "
                    "necessary capabilities). Operations may fail.")

    try:
        username = config.get('System', 'User')

        try:
            limited_user = pwd.getpwnam(username)
            if limited_user is not None:
                can_drop_privs = True
        except KeyError:
            logger.warn("User '%s' does not exist. Cannot switch " \
                        "to it." % username)
    except configparser.NoSectionError as e:
        logger.warn("No less-privileged user specified in config file. " \
                    "Please add a '[System]' section with the 'User' " \
                    "option specifying the username.")
    except configparser.NoOptionError as e:
        logger.warn("No less-privileged user specified in config file. " \
                    "Please add the 'User' option to the '[System]' " \
                    "section specifying the username.")

    return limited_user, can_drop_privs
