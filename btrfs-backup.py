#!/usr/bin/env python3

import argparse
import json
import os
import os.path
import time
import subprocess
import socket
import sys

qflag = False

class btrfs_backup:

    # Global variables/defaults
    HOME = '/var/lib/btrfs-backup'
    DATE = time.localtime()
    CONFIGFILE = HOME + '/config'
    CONF = None
    qflag = False

    class PrivilegedExit(Exception):
        '''Raised when the privileged version of this process/class exits'''
        pass

    class PasswordException(Exception):
        '''Raised by any error with the password'''
        pass

    def __init__(self):
        self.HOME       = self.__class__.HOME
        DATE            = self.__class__.DATE
        self.CONFIGFILE = self.__class__.CONFIGFILE
        self.CONF       = self.__class__.CONF
        self.qflag      = self.__class__.qflag
        self.DATE = '%04d-%02d-%02d-%02d' % (DATE.tm_year, DATE.tm_mon, DATE.tm_mday, DATE.tm_hour)

    def pr(self, msg):
        if not self.qflag:
            print(msg)
        return

    def parseargs(self, args):
        CONFIGFILE = self.CONFIGFILE # For easier reference

        # Main parser
        parser = argparse.ArgumentParser(\
            description='Tool to manage backups of Btrfs filesystems')

        # Global Arguments/Switches
        parser.add_argument('-q', '--quiet', \
            action='store_true', dest='quiet', default=False, \
            help='If specified, do not print status messages')
        parser.add_argument('-f', dest='file', default=CONFIGFILE,\
            help='Specify alternate configuration file (default is %s)' % \
            CONFIGFILE)
        subparsers = parser.add_subparsers(dest='verb', \
            help='subcommand to run')

        # Keyring (starting it)
        verb_keyring = subparsers.add_parser('keyring', \
            help='Start the keyring')

        # List backup configurations
        verb_list = subparsers.add_parser('list', \
            help='List all backups configurations')

        # Snapshot local filesystems
        verb_snapshot = subparsers.add_parser('snapshot', \
            help='Snapshot local filesystem(s)')

        self.args = parser.parse_args(args)
        self.qflag = self.args.quiet
        self.CONFIGFILE = self.args.file

        return

    def turn_root(self, argv):
        '''Function to make sure we run as root'''

        args = []

        # Check if we're already root
        if os.getuid() == 0:
            return

        self.pr('+ Changing to root')

        args.extend(argv)
        args.insert(0, 'sudo')
        returncode = subprocess.call(args)

        if returncode != 0:
            self.pr('+ Privileged process exited non-zero (%d)' % returncode)

        self.pr('+ Exited from privileged process')
        raise self.__class__.PrivilegedExit

    def parseconfig(self):
        # For easier reference
        CONFIGFILE = self.CONFIGFILE

        self.pr('+ Parsing %s' % CONFIGFILE)
        CONFIGFILE = os.path.abspath(CONFIGFILE)
        CONFIGFILE = os.path.realpath(CONFIGFILE)
        self.CONFIGFILE = CONFIGFILE

        self.pr('+ Using %s' % CONFIGFILE)

        try:
            # Make sure this is explicitly readable by root
            if not os.access(CONFIGFILE, os.R_OK, effective_ids=True):
                raise PermissionError(CONFIGFILE)

            with open(CONFIGFILE, 'r') as f:

                self.CONF = json.load(f)

        except Exception as e:
            # Optionally test these things for more descriptive error message
            # os.path.exists(CONFIGFILE)
            # os.path.isfile(CONFIGFILE)
            print('ERROR: Could not load config file, %s' % CONFIGFILE, \
                file=sys.stderr, flush=True)
            raise

        else:
            os.environ['HOME'] = self.CONF['dirs']['home']

    def run(self):
        '''Method to execute the command given'''

        if self.args.verb == 'keyring':
            self.keyring()
            return

        if self.args.verb == 'list':
            self.list()
            return

        if self.args.verb == 'snapshot':
            self.snapshot()
            return

        return

    def keyring(self):
        '''Method which starts the keyring/dbus session'''

        # For easier reference
        dirs    = self.CONF['dirs']
        dbus    = os.path.join(dirs['run'], 'dbus')
        keyring = os.path.join(dirs['run'], 'keyring')
        home    = dirs['home']

        # Start the dbus instance
        with open(dbus, 'w') as fo:
            self.pr('+ Starting dbus session')
            output = subprocess.check_output(('dbus-launch',)).decode()

            # Save the output to a standard location
            self.pr('+ Saving dbus information')
            fo.write(output)

            # Fine the address needed by other processes and put it into the
            # environment
            self.pr('+ Parsing dbus output')
            for line in output.splitlines():
                self.pr('+ Found %s' % line)

                var, val = line.split('=', 1)
                if var == 'DBUS_SESSION_BUS_ADDRESS':
                    os.environ[var] = val

        # Start the Gnome keyring
        with open(keyring, 'w') as fo:
            self.pr('+ Starting the Gnome keyring')

            # This sets up a socket to listen for the keyring password
            self.ask()

            output = subprocess.check_output(('gnome-keyring-daemon', \
                '--unlock', '-c', 'secrets,ssh', '-d'), input=self.pw).decode()

            # Save the output to a standard location
            self.pr('+ Saving keyring information')
            fo.write(output)

            self.pr('+ Parsing keyring output')
            for line in output.splitlines():
                self.pr('+ Found %s' % line)

                var, val = line.split('=', 1)
                os.environ[var] = val


    def ask(self):
        '''Method which attempts to read a password from the system'''

        fcontent = '''[Ask]
Message=Btrfs Backups Key
PID=%d
Echo=0
Socket=/run/btrfs-backup/ask
NotAfter=0
''' % os.getpid()

        fon = '/run/systemd/ask-password/ask.btrfs-backup'
        sock = '/run/btrfs-backup/ask'

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
                s.bind(sock)

                with open(fon, 'w') as fo:
                    fo.write(fcontent)

                s.settimeout(60.0)
                resp = s.recv(1024)

                if resp[0] == '-':
                    sys.stderr.write('Failed to read in btrfs-backup password')
                    raise self.__class__.PasswordException('Failed to read')

        except:
            raise

        else:
            self.pw = resp.decode().strip('\0')[1:].encode()
            with open('/run/btrfs-backup/pw', 'w') as f:
                f.write(self.pw.decode())

        finally:
            os.unlink(sock)
            os.unlink('/run/systemd/ask-password/ask.btrfs-backup')

        return

    def list(self):
        for uuid in self.CONF['backups'].keys():
            print('UUID=%s, URI=%s' % (uuid, self.CONF['backups'][uuid]['uri']))

    def snapshot(self):
        # Easier referencing
        dirs = self.CONF['dirs']

        for uuid in self.CONF['backups'].keys():
            backup = self.CONF['backups'][uuid]

            self.pr('+ Snapshotting backup with id %s' % uuid)

            returncode = subprocess.call(('mount', '-o', 'subvolid=0', \
                'UUID=%s' % backup['localuuid'], dirs['self']))
            if returncode != 0:
                raise Exception('Mounting local filesystem failed')

            try:
                for vol in backup['volumes']:
                    self.pr('+ Snapshotting subvolume %s at %s' % (vol, self.DATE))
                    path = os.path.join(dirs['self'], vol)

                    returncode = subprocess.call(('btrfs', 'subvolume', \
                        'snapshot', '-r', path, '%s-%s' % (path, self.DATE)),
                        stdout=open(os.devnull, 'w'))

                    if returncode != 0:
                        raise Exception('Failed to snapshot volume %s' % vol)
            except:
                raise

            finally:
                subprocess.call(('umount', dirs['self']))
        return


if __name__ == '__main__':
    # This is just a good idea
    os.umask(0o77)

    try:
        prog = btrfs_backup()
        prog.parseargs(sys.argv[1:])

        # Set our own qflag
        qflag = prog.qflag

        prog.turn_root(sys.argv[:])
        prog.parseconfig()

        # Execute the operation
        prog.run()

    except btrfs_backup.PrivilegedExit as e:
        if not qflag:
            print('+ Exiting')
        raise SystemExit(0) from e

    except Exception as e:
        if not qflag:
            print('+ Got Exception %s: %s' % (e.__class__.__name__, str(e)))
        raise SystemExit(1)

    except:
        print('An unknown error occurred; Exiting', file=sys.stderr)
        raise SystemExit(1)
