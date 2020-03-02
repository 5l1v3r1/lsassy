# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com [FR]
#  https://en.hackndo.com [EN]

import time
from socket import getaddrinfo, gaierror

from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SMBConnection, SessionError

from lsassy.utils.defines import *
from lsassy.modules.logger import Logger


class ImpacketConnection:
    class Options:
        def __init__(self, hostname="", domain_name="", username="", password="", lmhash="", nthash="", timeout=5):
            self.hostname = hostname
            self.domain_name = domain_name
            self.username = username
            self.password = password
            self.lmhash = lmhash
            self.nthash = nthash
            self.timeout = timeout

    def __init__(self, options: Options):
        self.options = options
        self.hostname = options.hostname
        self.domain_name = options.domain_name
        self.username = options.username
        self.password = options.password
        self.lmhash = options.lmhash
        self.nthash = options.nthash
        self.timeout = options.timeout
        self._log = Logger(self.hostname)
        self._conn = None

    def get_logger(self):
        return self._log

    def set_logger(self, logger):
        self._log = logger

    def login(self):
        try:
            ip = list({addr[-1][0] for addr in getaddrinfo(self.hostname, 0, 0, 0, 0)})[0]
            if ip != self.hostname:
                self._log.debug("Host {} resolved to {}".format(self.hostname, ip))
        except gaierror as e:
            self._log.error(ERROR_DNS_ERROR)
            raise
        except Exception:
            raise

        try:
            self._conn = SMBConnection(ip, ip, timeout=self.timeout)
        except Exception:
            self._log.error(ERROR_CONNECTION_ERROR)
            raise

        username = self.username.split("@")[0]
        self._log.debug("Authenticating against {}".format(ip))
        try:
            self._conn.login(username, self.password, domain=self.domain_name, lmhash=self.lmhash, nthash=self.nthash, ntlmFallback=True)
        except SessionError as e:
            self._log.debug("Provided credentials : {}\\{}:{}".format(self.domain_name, username, self.password))
            self._log.error(ERROR_LOGIN_FAILURE)
            raise
        except Exception:
            raise
        return ERROR_SUCCESS

    def connectTree(self, share_name):
        return self._conn.connectTree(share_name)

    def openFile(self, tid, fpath, timeout: int = 3):
        self._log.debug("Opening file {}".format(fpath))

        start = time.time()

        while True:
            try:
                fid = self._conn.openFile(tid, fpath, desiredAccess=FILE_READ_DATA)
                self._log.debug("File {} opened".format(fpath))
                return fid
            except Exception:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0 or str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                    # Output not finished, let's wait
                    if time.time() - start > timeout:
                        raise
                    time.sleep(1)
                else:
                    raise

    def queryInfo(self, tid, fid):
        while True:
            try:
                info = self._conn.queryInfo(tid, fid)
                return info
            except Exception:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(2)
                else:
                    raise

    def getFile(self, share_name, path_name, callback):
        while True:
            try:
                self._conn.getFile(share_name, path_name, callback)
                break
            except Exception:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(2)
                else:
                    raise

    def deleteFile(self, share_name, path_name):
        while True:
            try:
                self._conn.deleteFile(share_name, path_name)
                self._log.debug("File {} deleted".format(path_name))
                break
            except Exception:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    time.sleep(2)
                else:
                    raise

    def putFile(self, share_name, path_name, callback):
        try:
            self._conn.putFile(share_name, path_name, callback)
            self._log.debug("File {} uploaded".format(path_name))
        except Exception:
            self._log.error("An error occurred while uploading %s on %s share : %s" % (path_name, share_name, e))
            raise

    def readFile(self, tid, fid, offset, size):
        return self._conn.readFile(tid, fid, offset, size, singleCall=False)

    def closeFile(self, tid, fid):
        return self._conn.closeFile(tid, fid)

    def disconnectTree(self, tid):
        return self._conn.disconnectTree(tid)

    def isadmin(self):
        try:
            self.connectTree("C$")
            return ERROR_SUCCESS
        except Exception:
            return ERROR_ACCESS_DENIED

    def close(self):
        if self._conn is not None:
            self._log.debug("Closing Impacket connection")
            self._conn.close()

    def clean(self):
        try:
            self.close()
            return ERROR_SUCCESS
        except Exception:
            self._log.error(ERROR_CONNECTION_CLEANING)
            raise
