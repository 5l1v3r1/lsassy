# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

class RetCode:
    def __init__(self, error_code, error_msg):
        self.error_code = error_code
        self.error_msg = error_msg

    def __str__(self):
        return self.error_msg

    def __eq__(self, other):
        if isinstance(other, RetCode):
            return self.error_code == other.error_code
        elif isinstance(other, int):
            return self.error_code == other
        return NotImplemented

    def __ne__(self, other):
        x = self.__eq__(other)
        if x is not NotImplemented:
            return not x
        return NotImplemented

    def __hash__(self):
        return hash(tuple(sorted(self.__dict__.items())))

    def __nonzero__(self):
        return self.error_code == 0


ERROR_SUCCESS               = RetCode(0, "")
ERROR_NO_CREDENTIAL_FOUND   = RetCode(0, "Procdump could not be uploaded")

ERROR_MISSING_ARGUMENTS     = RetCode(1, "")
ERROR_CONNECTION_ERROR      = RetCode(2, "Connection error")
ERROR_ACCESS_DENIED         = RetCode(3, "Access denied. Administrative rights on remote host are required")
ERROR_METHOD_NOT_SUPPORTED  = RetCode(4, "Method not supported")
ERROR_LSASS_PROTECTED       = RetCode(5, "Lsass is protected")
ERROR_SLOW_TARGET           = RetCode(6, "Either lsass is protected or target might be slow or procdump/dumpert wasn't provided")
ERROR_LSASS_DUMP_NOT_FOUND  = RetCode(7, "lsass dump file does not exist. Use -vv flag for more details")
ERROR_USER_INTERRUPTION     = RetCode(8, "lsassy has been interrupted")
ERROR_PATH_FILE             = RetCode(9, "Invalid path")
ERROR_SHARE                 = RetCode(10, "Error opening share")
ERROR_FILE                  = RetCode(11, "Error opening file")
ERROR_INVALID_FORMAT        = RetCode(12, "Invalid format")
ERROR_DNS_ERROR             = RetCode(13, "No DNS found to resolve this hostname")
ERROR_LOGIN_FAILURE         = RetCode(14, "Authentication error")
ERROR_PROCDUMP_NOT_FOUND    = RetCode(15, "Procdump path is not valid")
ERROR_PROCDUMP_NOT_PROVIDED = RetCode(16, "Procdump was not provided")
ERROR_PROCDUMP_NOT_UPLOADED = RetCode(17, "Procdump could not be uploaded")
ERROR_DLL_NO_EXECUTE        = RetCode(18, "Could not execute commands on remote host via DLL method")
ERROR_PROCDUMP_NO_EXECUTE   = RetCode(19, "Could not execute commands on remote host via Procdump method")
ERROR_DUMPERT_NO_EXECUTE    = RetCode(20, "Could not execute commands on remote host via Dumpert method")
ERROR_DUMPERT_NOT_FOUND     = RetCode(21, "dumpert path is not valid")
ERROR_DUMPERT_NOT_PROVIDED  = RetCode(22, "dumpert was not provided")
ERROR_DUMPERT_NOT_UPLOADED  = RetCode(23, "dumpert could not be uploaded")
ERROR_OUTPUT_FORMAT_INVALID = RetCode(24, "Output format is not valid")
ERROR_OUTPUT_DIR_NOT_EXIST  = RetCode(25, "Output directory does not exist")

# Cleaning errors
ERROR_DUMP_CLEANING         = RetCode(100, "Error while cleaning lsass dump")
ERROR_PROCDUMP_CLEANING     = RetCode(101, "Error while cleaning procdump")
ERROR_DUMPERT_CLEANING      = RetCode(102, "Error while cleaning dumpert")
ERROR_CONNECTION_CLEANING   = RetCode(103, "Error while cleaning connection")

ERROR_UNDEFINED             = RetCode(-1, "Unknown error")



