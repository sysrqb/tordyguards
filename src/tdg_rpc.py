try:
    import cPickle as pickle
except ImportError:
    import pickle

from io import StringIO
from io import BytesIO
import select
import time
from common import *
from tdg_logging import *

VALID_RPC = dict((('dir_exists', rpc_dir_exists),
                  ('file_exists', rpc_file_exists),
                  ('create_state_store', rpc_create_state_store),
                  ('suspend_tor', rpc_suspend_tor),
                  ('resume_tor', rpc_resume_tor),
                  ('start_tor', rpc_start_tor_process),
                  ('stop_tor', rpc_stop_tor_process),
                  ('copy_file', rpc_cp_file),
                  ('move_file', rpc_mv_file),
                  ('get_list_of_known_networks',
                   rpc_get_list_of_known_networks),
                  ('update_last_ebssid_file',
                   rpc_update_last_ebssid_file),
                  ('read_file', rpc_read_file),))

ipc_pipes = {'pread_fd': None,
             'cread_fd': None,
             'pwrite_fd': None,
             'cwrite_fd': None,
}

LEN_SIZE = 8

child_pid = None
ppid = None

class RunWithPrivs(object):
    method = None
    nparam = 0
    params = tuple()
    result = 0
    result_string = None
    error = False

    def __init__(self, method=None, nparam=0, params=tuple()):
        if method:
            self.method = method.encode('utf8')
        self.nparam = nparam
        self.params = params

    def _send(self, write):
        msg = BytesIO()
        pklr = pickle.Pickler(msg, pickle.HIGHEST_PROTOCOL)
        pklr.dump(self)
        msg.seek(0, 2)
        msglen = msg.tell()
        msg.seek(0, 0)
        msglen_str = str(msglen)
        while len(msglen_str) != LEN_SIZE:
            msglen_str = '0' + msglen_str
        write.write(msglen_str)
        #os.fsync(write)
        write.flush()
        write.write(msg.read())
        #os.fsync(write)
        write.flush()

    def execute(self, write):
        self._send(write)

    def _read(self, read):
        msglen_str = read.read(LEN_SIZE)
        if msglen_str == '':
            # EOF, child likely exited. We should do the same
            return None
        msglen = int(msglen_str, 10)
        msg = read.read(msglen)
        pickled_msg = BytesIO(msg)
        unpklr = pickle.Unpickler(pickled_msg)
        return unpklr

    def result(self, read):
        unpklr = self._read(read)
        if unpklr == None:
            return None
        result = unpklr.load()
        self.result = result.result
        self.result_string = result.result_string
        return self

    def read_request(self, read):
        unpklr = self._read(read)
        if unpklr == None:
            return None
        request = unpklr.load()
        self.method = request.method
        self.nparam = request.nparam
        self.params = request.params
        return self

    def send_result(self, write):
        self._send(write)

TIMEOUT = 10
def main_priv_loop(read, write):
    write_queue = list()
    while True:
        (ready_read, ready_write, ready_ex) = \
            select.select([read], [write], [], TIMEOUT)
        if ready_read:
            logger.info("Received request.")
            req = RunWithPrivs()
            if req.read_request(ready_read[0]) == None:
                logger.info("Unpriv'd connection closed. Breaking.")
                break
            logger.info("Received request for '%s'" % req.method)
            res = handle_request(req)
            write_queue.append(res)
            logger.info("Appending response to the queue")
        if ready_write:
            #logger.dkbug("Pipe is ready for writing")
            if len(write_queue) > 0:
                logger.info("Write queue has %d response(s) pending" % \
                            (len(write_queue)))
                res = write_queue.pop()
                res.send_result(ready_write[0])

def handle_request(request):
    try:
        if request.nparam:
            logger.info("Request has %d parameter(s)" % request.nparam)
        if not (request.method or request.nparam or request.params):
            logger.info("Received empty request")
            request.result = False
            request.result_string = "Unknown how to call method"
            request.error = True
            return request
        if request.nparam == 0:
            logger.info("Calling %s()" % \
                        (VALID_RPC[request.method]))
            request.error, request.result, request.result_string = \
                    VALID_RPC[request.method]()
            return request
        elif request.nparam == 1:
            param = request.params[0]
            logger.info("Calling %s(%s)" % \
                        (VALID_RPC[request.method], param))
            request.error, request.result, request.result_string = \
                    VALID_RPC[request.method](param)
            return request
        elif request.nparam == 2:
            param = request.params
            logger.info("Calling %s(%s, %s)" % \
                        (VALID_RPC[request.method], param[0], param[1]))
            request.error, request.result, request.result_string = \
                    VALID_RPC[request.method](param[0], param[1])
            return request
        elif request.nparam > 2:
            logger.info("Received request with too many parameters")
            request.result = False
            request.result_string = "Too many parameters specified"
            request.error = True
            return request
    except (TypeError, KeyError) as e:
        logger.warn("Caught exception! %s" % e.message)
        request.result = False
        request.result_string = "Method invocation failed: %s" % e.message
        request.error = True
        return request

    

