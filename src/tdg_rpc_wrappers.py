from tdg_logging import *
from common import *
from tdg_rpc import *

read_fd = None
write_fd = None
privsep = False

def create_state_store(path):
    if privsep:
        rwp = RunWithPrivs('create_state_store', 1, (path,))
        logger.info("Requesting create_state_store")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("create_state_store: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling create_state_store")
        return create_state_store_(path)

def file_exists(state_full_path):
    if privsep:
        rwp = RunWithPrivs('file_exists', 1, (state_full_path,))
        logger.info("Requesting file_exists")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("file_exists: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling file_exists")
        return file_exists_(state_full_path)

def dir_exists(dirpath):
    if privsep:
        rwp = RunWithPrivs('dir_exists', 1, (dirpath,))
        logger.info("Requesting dir_exists")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("dir_exists: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling dir_exists")
        return dir_exists_(dirpath)

def mv_file(from_file, to_file):
    if privsep:
        rwp = RunWithPrivs('move_file', 2, (from_file, to_file,))
        logger.info("Requesting move_file")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("mv_file: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling move_file")
        mv_file_(from_file, to_file)

def cp_file(from_file, to_file, user=None):
    if not user:
        user = os.getlogin()
    if privsep:
        rwp = RunWithPrivs('copy_file', 3, (from_file, to_file, user,))
        logger.info("Requesting copy_file")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("cp_file: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling copy_file")
        cp_file_(from_file, to_file, user)

def start_tor_process(start_tor):
    if privsep:
        rwp = RunWithPrivs('start_tor', 1, (start_tor,))
        logger.info("Requesting start_tor")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("start_tor_process: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling start_tor")
        start_tor_process_(start_tor)

def stop_tor_process(stop_tor):
    if privsep:
        rwp = RunWithPrivs('stop_tor', 1, (stop_tor,))
        logger.info("Requesting stop_tor")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("stop_tor_process: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling stop_tor")
        stop_tor_process_(stop_tor)

def suspend_tor(pid):
    if privsep:
        rwp = RunWithPrivs('suspend_tor', 1, (pid,))
        logger.info("Requesting suspend_tor")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("suspend_tor: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling suspend_tor")
        suspend_tor_(pid)

def resume_tor(pid):
    if privsep:
        rwp = RunWithPrivs('resume_tor', 1, (pid,))
        logger.info("Requesting resume_tor")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("resume_tor: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling resume_tor")
        resume_tor_(pid)

def get_list_of_known_networks(path):
    if privsep:
        rwp = RunWithPrivs('get_list_of_known_networks', 1, (path,))
        logger.info("Requesting get_list_of_known_networks")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("get_list_of_known_networks: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling get_list_of_known_networks")
        get_list_of_known_networks_(pid)

def update_last_ebssid_file(last_ebssid_fp, ebssid):
    if privsep:
        rwp = RunWithPrivs('update_last_ebssid_file', 2,
                           (last_ebssid_fp, ebssid,))
        logger.info("Requesting update_last_ebssid_file")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("update_last_ebssid_file: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling update_last_ebssid_file")
        update_last_ebssid_file_(last_ebssid_fp, ebssid)

def read_file(fn):
    if privsep:
        rwp = RunWithPrivs('read_file', 1, (fn,))
        logger.info("Requesting read_file")
        rwp.execute(write_fd)
        rwp = rwp.result(read_fd)
        if rwp == None:
            logger.info("It looks like priv'd conn closed.")
        else:
            if rwp.error:
                logger.warn("read_file: Failure: %s (%s)" % \
                            (rwp.result_string, rwp.result))
            return rwp.result
    else:
        logger.info("Calling read_file")
        return read_file_(fn)
