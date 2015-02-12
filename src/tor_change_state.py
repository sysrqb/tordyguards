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
    * The last bssid we connected to
    * The current bssid we are connecting to
    
    Possible cases with those variables:
    * state file does not exit, no last bssid =>
      action: update last_bssid file with current bssid
    * state file does not exit, last bssid, last bssid != current bssid =>
      action: mv state.bssid_previous state;
              update last_bssid file with current bssid
    * state file does not exit, last bssid, last bssid == current bssid =>
      action: cp state state.bssid_previous
    * state file exits, no last bssid =>
      action: mv state state.old, update last bssid file
    * state file exits, last bssid, last bssid != current bssid =>
      action: mv state state.bssid_previous; cp state.bssid state,
              update last_bssid file with current bssid
    * state file exits, last bssid, last bssid == current bssid =>
      action: cp state state.bssid
    
    :param bssid: bssid
    :type bssid: string
    :param state_path: parent path to the tor default state file
    :type state_path: string
    :param state_fn: file name of the tor default state file
    :type state_fn: string
    :param last_bssid_fn: file name where the last bssid is stored
    :type last_bssid_fn: string
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
    last_bssid_fn = config.get('Network', 'LastBSSIDFilename')
    start_tor = config.get('Commands', 'StartTor')
    stop_tor = config.get('Commands', 'StopTor')

    last_bssid_fp = last_bssid_full_path(state_path, last_bssid_fn)
    state_fp = state_full_path(state_path, state_fn)
    state_bssid_fp = state_bssid_full_path(state_path, state_fn, bssid)
    state_old_fp = state_old_full_path(state_path, state_fn)

    previous_bssid = last_bssid_file_exists(last_bssid_fp)
    if previous_bssid:
        state_bssid_previous_fp = state_bssid_full_path(
            state_path, state_fn, previous_bssid)
        if file_exists(state_fp):
            if previous_bssid != bssid:
                # before using state file, stop tor
                logger.info("stopping tor")
                os.system(stop_tor)
                mv_file(state_fp, state_bssid_previous_fp)
                if file_exists(state_bssid_fp):
                    cp_file(state_bssid_fp, state_fp)
                # else: no state.bssid_previous
                # current state will be created by tor
                update_last_bssid_file(last_bssid_fp, bssid)
            else:
                # else: previous_bssid == bssid
                # no need to cp state to state.bssid, nor to update last_bssid
                # but update state.bssid with last state
                # don't stop tor to don't loose the circuits
                cp_file(state_fp, state_bssid_fp)
        else:
            # else: no state file
            if previous_bssid != bssid:
                if file_exists(state_bssid_previous_fp):
                    logger.info("stopping tor") 
                    os.system(stop_tor) 
                    mv_file(state_bssid_previous_fp, state_fp)
                # else: no state.last_bssid file
                # current state will be created by tor
                update_last_bssid_file(last_bssid_fp, bssid)
            # else: previous_bssid == bssid
            # no need to mv state, no need to update last_bssid
    else:
        # else: no last_bssid file
        if file_exists(state_fp):
            mv_file(state_fp, state_old_fp)
        update_last_bssid_file(last_bssid_fp, bssid)

    # start tor again (if it wasn't stop it, it won't do anything)
    logger.info("starting tor")
    os.system(start_tor)
