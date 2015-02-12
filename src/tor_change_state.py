"""
    Change the Tor state file depending on the network bssid.
"""

#   This file is part of TorDyGuards, a set of scripts to
#   use different tor guards depending on the network we connect to.
#
#   Copyright (C) 2014 Lee Woboo (leewoboo at riseup dot net)
#
#   TorDyGuards is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License Version 3 of the
#   License, or (at your option) any later version.
#
#   TorDyGuards is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with TorDyGuards.  If not, see <http://www.gnu.org/licenses/>.
#

# ConfigParser module has been renamed to configparser in Python 3
try:
    import configparser
except:
    import ConfigParser as configparser
import os
from common import *
from tdg_logging import *

#tor_wicd_conf = os.path.join("/etc/wicd/", "tor_wicd.conf")

def parseConfig(filename=None):
    try:
        fh = open(filename)
    except (IOError, OSError):
        logger.warn("Couldn't open config file: %s" % filename)
        raise SystemExit()

    try:
        config = configparser.ConfigParser()
        # in Python 2 there the method is called readfp
        try:
            config.read_file(fh)
        except:
            config.readfp(fh)
        if not 'Tor' in config.sections():
            raise ValueError("Couldn't parse config file: %s" % filename)
    except Exception, error:
        raise SystemExit(error)
    else:
        fh.close()

    return config

def change_state_file(config_file):
    """Change tor state file depending on the network ebssid
    
    Tor ignore state file when it is a symlink,
    so this create a file to store the last bssid
    and update the state.bssid files according to that file
    
    There are 3 main variables to take into account:
    * The default tor state file
    * The last essid/bssid we connected to
    * The current essid/bssid we are connecting to

    The essid/bssid combination is referred to as ebssid.
    
    Possible cases with those variables:
    * case 1: if state file does not exist and the previous ebssid is unknown =>
      action: update previous ebssid file with current ebssid.
    * case 2: if state file does not exist, the previous ebssid is known,
         and ${previous_ebssid} != ${ebssid} =>
      action: mv state.${ebssid_previous} state;
              update previous_ebssid file with current ebssid
    * case 3: state file does not exit, last ebssid, last ebssid == current ebssid =>
      action: None
    * case 4: state file exits, no last ebssid =>
      action: mv state state.old, update last ebssid file
    * case 5: state file exits, last ebssid, last ebssid != current ebssid =>
      action: mv state state.ebssid_previous; cp state.ebssid state,
              update last_ebssid file with current ebssid
    * case 6: state file exits, last ebssid, last ebssid == current ebssid =>
      action: cp state state.ebssid
    
    :param essid: essid
    :type essid: string
    :param bssid: bssid
    :type bssid: string
    :param ebssid: ebssid
    :type ebssid: string
    :param state_path: parent path to the tor default state file
    :type state_path: string
    :param state_fn: file name of the tor default state file
    :type state_fn: string
    :param last_ebssid_fn: file name where the last bssid is stored
    :type last_ebssid_fn: string
    """

    bssid = None
    essid = None
    manager = None
    config = parseConfig(config_file)

    # Suspend Tor early
    pid = 1
    pid_fn = config.get('Tor', 'PidFile')
    pidstr = read_file(pid_fn)
    if not pidstr:
        pid = int(pidstr)
        suspend_tor(pid)

    if config.get('Manager', 'Wicd') == "Yes":
        from wicd_tor_change_state import WicdManager
        logger.info("Using Wicd.")
        manager = WicdManager()
    elif config.get('Manager', 'NetworkManager') == "Yes":
        from nm_tor_change_state import NMManager
        logger.info("Using NetworkManager.")
        manager = NMManager()
    else:
        logger.error("Unknown Manager. Done.")
        resume_tor(pid)
        return

    manager.parse_args()
    logger.info("Getting devices, if needed.")
    if manager.need_devices():
        manager.set_devices(init_devices_lists())
    logger.info("Checking if we should abort here.")
    if not manager.should_continue():
        logger.info("Manager decided we should not continue.")
        resume_tor(pid)
        return
    logger.info("Continuing...")

    essid, bssid = manager.get_ebssid()

    logger.info("ESSID: %s, BSSID: %s" % (essid, bssid))
    datadir_path = config.get('Tor', 'DataDirectory')
    statestore_path = config.get('Tor', 'StateStorage')
    state_fn = config.get('Tor', 'StateFile')
    last_ebssid_fn = config.get('Network', 'LastEBSSIDFilename')
    start_tor = config.get('Commands', 'StartTor')
    stop_tor = config.get('Commands', 'StopTor')

    if not create_state_store(statestore_path):
        logger.warn("Couldn't create State Storage (%s) . Failing." % \
                    statestore_path)
        resume_tor(pid)
        return

    essid, bssid = get_or_prompt_for_ebssid(essid, bssid,
                                            statestore_path)

    ebssid = essid + '.' + bssid
    if ebssid == ".":
        logger.warn("We've got nothing. Quiting while we're ahead.")
        return

    last_ebssid_fp = last_ebssid_full_path(statestore_path, last_ebssid_fn)
    state_fp = state_full_path(datadir_path, state_fn)
    state_ebssid_fp = state_ebssid_full_path(statestore_path, essid, bssid)
    state_old_fp = state_old_full_path(statestore_path, state_fn)
    previous_ebssid = last_ebssid_file_exists(last_ebssid_fp)
    if previous_ebssid:
       previous_ebssid, previous_essid, previous_bssid = \
               get_previous_e_and_b_ssids(previous_ebssid)
       state_ebssid_previous_fp = \
               state_ebssid_full_path(statestore_path,
                                      previous_essid,
                                      previous_bssid)

    if previous_ebssid:
        if file_exists(state_fp):
            if previous_ebssid != ebssid:
                logger.info("Case 5: Known previous, current "
                            "state, different network")
                # before using state file, stop tor
                resume_tor(pid)
                stop_tor_process(stop_tor)
                mv_file(state_fp, state_ebssid_previous_fp)
                if file_exists(state_ebssid_fp):
                    cp_file(state_ebssid_fp, state_fp)
                # else: no state.bssid_previous
                # current state will be created by tor
                update_last_ebssid_file(last_ebssid_fp, ebssid)
            else:
                logger.info("Case 6: Known previous, current "
                            "state, same network")
                # else: previous_ebssid == ebssid
                # no need to cp state to state.${ebssid}, nor to update
                # last_ebssid but update state.${ebssid} with last state
                # don't stop tor to don't loose the circuits
                cp_file(state_fp, state_ebssid_fp)
                resume_tor(pid)
        else:
            # else: no state file
            if previous_ebssid != ebssid:
                logger.info("Case 2: Known previous, no current "
                            "state.")
                if file_exists(state_ebssid_previous_fp):
                    resume_tor(pid)
                    stop_tor_process(stop_tor)
                    mv_file(state_ebssid_previous_fp, state_fp)
                # else: no state.${last_ebssid} file
                # current state will be created by tor
                update_last_ebssid_file(last_ebssid_fp, ebssid)
            else:
                #previous_ebssid == ebssid
                # no need to mv state, no need to update last_ebssid
                logger.info("Case 3: Known previous, current "
                            "state network matches new network.")
                resume_tor(pid)
    else:
        # else: no last_ebssid file
        resume_tor(pid)
        stop_tor_process(stop_tor)
        if file_exists(state_fp):
            logger.info("Case 4: Unknown previous, current "
                        "state, assuming different network")
            mv_file(state_fp, state_old_fp)
        else:
            logger.info("Case 1: Unknown previous, no current state.")
        update_last_ebssid_file(last_ebssid_fp, ebssid)

    # start tor again (if it wasn't stop it, it won't do anything)
    start_tor_process(start_tor)
