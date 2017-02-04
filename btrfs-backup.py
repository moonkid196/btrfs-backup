#!/usr/bin/env python3

import argparse
from bbcolor import bbcolor
import collections
import logging
import os
import os.path
import time
import subprocess
import socket
import sys
import tempfile
from urllib.parse import urlparse
import uuid
import yaml

qflag = not sys.stdout.isatty()

def get_logger(name, level=logging.DEBUG, full=True):
    if full:
        formatter = logging.Formatter(fmt='{asctime} {message}', style='{')
    else:
        formatter = logging.Formatter(fmt='{message}', style='')

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(level)

    logger = logging.Logger(name, level)
    logger.addHandler(handler)

    return logger

class btrfs_backup:

    # Global variables/defaults
    HOME = '/var/lib/btrfs-backup'
    DATE = time.localtime()
    CONFIGFILE = '{}/config.yaml'.format(HOME)
    CONF = None
    qflag = not sys.stdout.isatty()
    msgpre = bbcolor().format('+', foreground=21, style='normal')

    # Logging colors
    COLOR_ERROR = 31
    COLOR_WARN = 33
    COLOR_INFO = 32
    COLOR_DEBUG = 35

    # Old values
    COLOR_DEFAULT = 250
    COLOR_VALUE = 48

    class PrivilegedExit(Exception):
        '''Raised when the privileged version of this process/class exits'''
        pass

    class PasswordException(Exception):
        '''Raised by any error with the password'''
        pass

    def __init__(self):
        DATE = self.__class__.DATE
        self.DATE = '%04d-%02d-%02d-%02d' % (DATE.tm_year, DATE.tm_mon, DATE.tm_mday, DATE.tm_hour)
        self.logger = get_logger(__name__)
        self.color = True

    def _error(self, message):
        if self.color:
            mstring = '\033[{}mERROR: {}\033[0m'.format(self.COLOR_ERROR, message)
        else:
            mstring = 'ERROR: {}'.format(message)

        self.logger.error(mstring)

    def _warn(self, message):
        if self.color:
            mstring = '\033[{}mWARN: {}\033[0m'.format(self.COLOR_WARN, message)
        else:
            mstring = 'WARN: {}'.format(message)

        self.logger.warn(mstring)

    def _info(self, message):
        if self.color:
            mstring = '\033[{}m+ {}\033[0m'.format(self.COLOR_INFO, message)
        else:
            mstring = '+ {}'.format(message)

        self.logger.info(mstring)

    def _debug(self, message):
        if self.color:
            mstring = '\033[{}m+ {}\033[0m'.format(self.COLOR_DEBUG, message)
        else:
            mstring = '+ {}'.format(message)

        self.logger.debug(mstring)

    def pr(self, msg, file=sys.stdout, bbc=None):

        self._warn('calling old pr() method')
        self._debug('message = {}'.format(msg))

    def parse_args(self, argv):
        CONFIGFILE = self.CONFIGFILE # For easier reference

        # Main parser
        parser = argparse.ArgumentParser(\
            description='Tool to manage backups of Btrfs filesystems')

        # Global Arguments/Switches
        vq = parser.add_mutually_exclusive_group()
        vq.add_argument('-q', '--quiet', action='store_true', dest='quiet', \
            default=False, help='If specified, do not print status messages')
        vq.add_argument('-v', '--verbose', dest='verbose', \
            action='store_true', default=False, \
            help='If specified, print status messages')

        parser.add_argument('-f', dest='file', default=CONFIGFILE, \
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
        verb_snapshot.add_argument('snapshot_uuid', type=uuid.UUID, \
            metavar='UUID', nargs=1, help='UUID of the backup profile to snapshot')

        # Mount a backup
        verb_mount = subparsers.add_parser('mount', \
            help='Mount the disks for a backup')
        verb_mount.add_argument('mount_uuid', type=uuid.UUID, \
            metavar='UUID', nargs=1, help='UUID of the backup to mount')

        # Unmount a backup
        verb_unmount = subparsers.add_parser('unmount', \
            help='Unmount the disks for a backup')
        verb_unmount.add_argument('unmount_uuid', type=uuid.UUID, \
            metavar='UUID', nargs=1, help='UUID of the backup to unmount')

        # Do a full run
        verb_backup = subparsers.add_parser('backup', \
            help='Perform a full backup run')
        verb_backup.add_argument('backup_uuid', type=uuid.UUID, \
            metavar='UUID', nargs=1, help='UUID of the backup profile to run')

        self.args = parser.parse_args(argv[1:])

        if self.args.quiet:
            self.qflag = True

        if self.args.verbose:
            self.qflag = False

        self.CONFIGFILE = self.args.file

        self._debug('qflag = {}'.format(self.qflag))
        self._debug('verb = {}'.format(self.args.verb))
        self._debug('CONFIGFILE = {}'.format(self.CONFIGFILE))

        if self.args.verb is None:
            self._error('No operation given')
            raise Exception('No operation given')

        return self

    def config(self):

        if self.CONF is not None:
            self._debug('returning cached config')
            return CONF

        # For easier reference
        CONFIGFILE = self.CONFIGFILE

        self._info('Parsing %s' % CONFIGFILE)
        CONFIGFILE = os.path.abspath(CONFIGFILE)
        CONFIGFILE = os.path.realpath(CONFIGFILE)
        self.CONFIGFILE = CONFIGFILE

        self._debug('Using %s' % CONFIGFILE)

        try:
            # Make sure this is explicitly readable by root
            with open(CONFIGFILE, 'r') as f:
                self.CONF = yaml.load(f)

        except PermissionError as e:
            self._error('Could not read config file; are you root?')
            raise SystemExit(1)

        else:
            os.environ['HOME'] = self.CONF['dirs']['home']

        return self.CONF

    def run(self, args=sys.argv[:]):
        '''Method to execute the command given'''

        self.parse_args(args)

        if self.args.verb == 'list':
            self.list()
            return

        if self.args.verb == 'keyring':
            self.keyring()
            return

        if self.args.verb == 'mount':
            self.keyring()
            self.mount(self.args.mount_uuid[0])
            return

        if self.args.verb == 'unmount':
            self.unmount(self.args.unmount_uuid[0])
            return

        if self.args.verb == 'snapshot':
            self.snapshot(self.args.snapshot_uuid[0])
            return

        if self.args.verb == 'backup':
            self.snapshot(self.args.backup_uuid[0])
            self.keyring()
            self.mount(self.args.backup_uuid[0])
            self.backup(self.args.backup_uuid[0])
            self.unmount(self.args.backup_uuid[0])

        return

    def mount(self, uuid):
        '''Method to handle mounting the disks for a backup'''

        uuid = str(uuid)
        if uuid not in self.CONF['backups'].keys():
            raise Exception('%s not a valid backup UUID' % uuid)

        backup = self.CONF['backups'][uuid]
        dirs   = self.CONF['dirs']

        self.cmd_mount(backup['localuuid'], dirs['self'])
        remote = self.parseuri(uuid)

        if remote.protocol == 'sshfs':
            self.pr('Checking if %s is alive' % remote.host)
            if not self.isalive(remote.host):
                raise Exception('Host %s could not be reached' % remote.host)

            self.pr('Mounting %s on %s' % (backup['uri'], dirs['remote']))
            returncode = subprocess.call(('sshfs', '%s@%s:%s' % \
                (remote.user, remote.host, remote.path), \
                dirs['remote']), stdout=subprocess.DEVNULL)
            if returncode != 0:
                raise Exception('Failed to mount %s' % backup['uri'])

        else:
            raise Exception('Unknown protocol: %s' % remote.protocol)

        image = os.path.join(dirs['remote'], remote.image)
        self.pr('Mapping %s to loop device' % image)
        device = self.losetup(image)

        if backup['encrypt']:
            luksUUID = self.luksUUID(device)
            luksdev  = 'luks-%s' % luksUUID

            self.pr('Reading encryption passphrase from gnome-keyring')
            pw = self.get_secret('disk', luksUUID)

            self.pr('Opening %s as %s' % (device, luksdev))
            self.cryptsetup('open', luksdev, device, pw)
            device = os.path.join('/dev/mapper', luksdev)

        self.pr('Mounting %s on %s' % (device, dirs['backups']))

        if backup['compress']:
            self.cmd_mount(device, dirs['backups'], uuid=False, \
                opts='subvolid=0,compress')
        else:
            self.cmd_mount(device, dirs['backups'], uuid=False)

        return

    def unmount(self, uuid):
        '''Method to handle unmounting backup disks'''

        uuid     = str(uuid)
        backup   = self.CONF['backups'][uuid]
        dirs     = self.CONF['dirs']
        remote   = self.parseuri(uuid)
        image    = os.path.join(dirs['remote'], remote.image)

        # Try to unmount the BTRFS volume. Since all of these operations are
        # non-destructive in a sense, we ignore errors and try to go on
        try:
            self.cmd_unmount(dirs['backups'])

        except Exception as e:
            self.bbc.pr('WARNING: %s' % str(e), foreground=self.COLOR_WARN)

        # Try to close the LUKS device
        if backup['encrypt']:
            try:
                loopdev  = self.losetup(image, verb='read')
                luksUUID = self.luksUUID(loopdev)
                self.pr('Closing luks-%s' % luksUUID)
                self.cryptsetup('close', 'luks-%s' % luksUUID)

            except Exception as e:
                self.bbc.pr('WARNING: %s' % str(e), foreground=self.COLOR_WARN)

        # Try to kill the loop device
        try:
            self.losetup(image, verb='delete')

        except Exception as e:
            self.bbc.pr('WARNING: %s' % str(e), foreground=self.COLOR_WARN)

        # Try to unmount the backups share
        try:
            if remote.protocol == 'sshfs':
                returncode = subprocess.call(('fusermount', '-qu', dirs['remote']))
                if returncode != 0:
                    raise Exception('Failed to unmount %s' % dirs['remote'])

        except Exception as e:
            self.bbc.pr('WARNING: %s' % str(e), foreground=self.COLOR_WARN)

        # Try to unmount the local volume
        try:
            self.pr('Unmounting %s' % dirs['self'])
            self.cmd_unmount(dirs['self'])

        except Exception as e:
            self.bbc.pr('WARNING: %s' % str(e), foreground=self.COLOR_WARN)

        return

    def luksUUID(self, device):
        '''Method to return the UUID of a LUKS device'''

        try:
            output = subprocess.check_output(\
                ('cryptsetup', 'luksUUID', device)).decode()

            # Sanity-checking the UUID
            myuuid = uuid.UUID(output.strip())

            self.pr('Found UUID %s for %s' % (str(myuuid), device))
            return str(myuuid)

        except subprocess.CalledProcessError:
            raise Exception('cryptsetup failed to produce a UUID')

    def get_secret(self, k, v):
        '''Method to look up secrets using secret-tool'''

        try:
            output = subprocess.check_output(\
                ('secret-tool', 'lookup', 'tool', 'btrfs-backup', k, v)\
                ).decode()

            return output.strip()

        except subprocess.CalledProcessError:
            raise Exception('Failed to read from the gnome-keychain')

    def cryptsetup(self, verb, luksdev, src=None, pw=None):
        '''Method to open/close LUKS devices'''

        if verb == 'open':
            if pw is None:
                raise Exception('Requested to open LUKS device with no password')
            if src is None:
                raise Exception('Requested to open LUKS device with no source device')

            with tempfile.TemporaryDirectory(dir='/dev/shm') as d:
                pfile = os.path.join(d, 'pfile')
                with open(pfile, 'w') as f:
                    f.write(pw)

                returncode = subprocess.call(('cryptsetup', '-q', 'open', \
                    src, luksdev, '--key-file', pfile))
                if returncode != 0:
                    raise Exception('Failed to open/decrypt %s' % src)

        elif verb == 'close':
            returncode = subprocess.call(('cryptsetup', 'close', luksdev))
            if returncode != 0:
                raise Exception('Failed to close %s' % luksdev)

        else:
            raise Exception('Got unknown verb %s in cryptsetup')

        return

    def losetup(self, image, verb='map'):
        '''Method to interact with the losetup tool'''

        loopdev = None

        try:
            output = subprocess.check_output(('losetup', '--raw', \
                '--noheadings', '--list')).decode()

            for line in output.splitlines():
                loop = line.split()
                if loop[-1] == image:
                    loopdev = loop[0]
                    self.pr('Found mapping %s => %s' % (image, loopdev))

            if verb == 'delete':
                if loopdev is None:
                    self.bbc.pr(\
                        'WARNING: %s is not mapped to any loop devices' % image, \
                        foreground=self.COLOR_WARN, file=sys.stderr)
                    return

                self.pr('Deleting %s' % loopdev)
                returncode = subprocess.call(('losetup', '-d', loopdev))
                if returncode != 0:
                    raise Exception('losetup -d %s returned non-zero' % loopdev)
                return

            if verb == 'read':
                if loopdev is None:
                    raise Exception('Loop device not found for %s' % image)
                return loopdev

            returncode = subprocess.call(('losetup', '-f', image))
            if returncode != 0:
                raise Exception('losetup -f %s returned non-zero' % image)

            output = subprocess.check_output(('losetup', '--raw', \
                '--noheadings', '--list')).decode()

            for line in output.splitlines():
                loop = line.split()
                if loop[-1] == image:
                    loopdev = loop[0]
                    self.pr('Mapped %s => %s' % (image, loopdev))
                    return loopdev

            raise Exception('losetup did not fail, but file never got mapped')

        except subprocess.CalledProcessError:
            raise Exception('losetup returned non-zero')

    def parseuri(self, uuid):
        uri = collections.namedtuple('uri', \
            ['protocol', 'user', 'host', 'path', 'image'])
        o = urlparse(self.CONF['backups'][uuid]['uri'])

        protocol = None
        user     = None
        host     = None
        path     = None
        image    = None

        self.pr('Setting remote protocol to %s' % o.scheme)
        protocol = o.scheme

        self.pr('Setting remote path to %s' % os.path.dirname(o.path))
        path     = os.path.dirname(o.path)

        self.pr('Setting remote image to %s' % os.path.basename(o.path))
        image    = os.path.basename(o.path)

        res = o.netloc.rpartition('@')

        self.pr('Setting remote host to %s' % res[2])
        host = res[2]

        if res[0] != '':
            self.pr('Setting remote user to %s' % res[0])
            user = res[0]

        remote = uri(protocol, user, host, path, image)
        return remote

    def isalive(self, host):
        '''Effectively runs "ping -qn -c 4 -w 6" against the remote host'''

        args = ('ping', '-q', '-n', '-c', '4', '-w', '6', host)
        returncode = subprocess.call(args, stdout=subprocess.DEVNULL)
        if returncode != 0:
            return False

        return True

    def keyring(self):
        '''Method which starts the keyring/dbus session'''

        # For easier reference
        dirs    = self.CONF['dirs']
        dbus    = os.path.join(dirs['run'], 'dbus')
        keyring = os.path.join(dirs['run'], 'keyring')
        home    = dirs['home']

        # Check for existing keyring
        if os.path.exists(dbus) and os.path.exists(keyring):
            self.pr('Found existing keyring')

            with open(dbus, 'r') as f:
                for line in f.readlines():
                    k,s,v = line.strip().partition('=')
                    self.pr('%s=%s' % (k, v))

                    if k == 'DBUS_SESSION_BUS_ADDRESS':
                        os.environ[k] = v

            with open(keyring, 'r') as f:
                for line in f.readlines():
                    k,s,v = line.strip().partition('=')
                    self.pr('Found %s=%s' % (k, v))

                os.environ[k] = v

            return

        # Start the dbus instance
        with open(dbus, 'w') as fo:
            self.pr('Starting dbus session')
            output = subprocess.check_output(('dbus-launch',)).decode()

            # Save the output to a standard location
            self.pr('Saving dbus information')
            fo.write(output)

            # Fine the address needed by other processes and put it into the
            # environment
            self.pr('Parsing dbus output')
            for line in output.splitlines():
                self.pr('Found %s' % line)

                var, val = line.split('=', 1)
                if var == 'DBUS_SESSION_BUS_ADDRESS':
                    os.environ[var] = val

        # Start the Gnome keyring
        with open(keyring, 'w') as fo:
            self.pr('Starting the Gnome keyring')

            # This sets up a socket to listen for the keyring password
            self.ask()

            output = subprocess.check_output(('gnome-keyring-daemon', \
                '--unlock', '-c', 'secrets,ssh', '-d'), input=self.pw).decode()

            # Save the output to a standard location
            self.pr('Saving keyring information')
            fo.write(output)

            self.pr('Parsing keyring output')
            for line in output.splitlines():
                self.pr('Found %s' % line)

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
            os.unlink('/run/btrfs-backup/pw')

        return

    def list(self):
        '''
        Lists the available configurations
        '''

        self._info('listing available configurations')

        config = self.config()

        for uuid in config['backups'].keys():
            uri  = config['backups'][uuid]['uri']

            print('UUID: {}'.format(uuid))
            print('    URI: {}'.format(uri))

    def snapshot(self, uuid):
        '''Snapshot a local disk'''

        self._info('snapshotting local disk')

        # Easier referencing
        config = self.config()
        dirs = config['dirs']
        uuid = str(uuid)

        if uuid not in config['backups']:
            message = 'UUID {} not a valid backup id'.format(uuid)
            self._error(message)
            raise Exception(message)

        self._debug('snapshotting backup with id = {}'.format(uuid))

        backup = config['backups'][uuid]

        try:
            self.cmd_mount(backup['localuuid'], dirs['self'])

            for volume in backup['volumes']:
                self._debug('snapshotting subvolume {}'.format(volume))
                path = os.path.join(dirs['self'], volume)
                snap = '{}-{}'.format(path, self.DATE)

                self.btrfs_snapshot(path, snap)

        finally:
            self.cmd_unmount(dirs['self'])

    def backup(self, uuid):
        '''Method which sends snapshots to the destination and ages local and
        remote snapshots'''

        dirs   = self.CONF['dirs']
        uuid   = str(uuid)
        backup = self.CONF['backups'][uuid]

        local_snapshots  = os.listdir(dirs['self'])
        remote_snapshots = os.listdir(dirs['backups'])

        return

    def btrfs_snapshot(self, path, snap, readonly=True):
        '''
Do a btrfs snapshot operation

Arguments:
  path = path to the subvolume
  snap = path to the snapshot
  readonly = (Default True) whether to make a readonly snapshot
'''

        self._info('snapshotting {} as {}'.format(path, snap))

        argv = ('btrfs', 'subvolume', 'snapshot', '-r', path, snap)

        self._debug('running {}'.format(' '.join(argv)))
        returncode = subprocess.call(argv, stdout=subprocess.DEVNULL)

        if returncode != 0:
            message = 'Failed to snapshot volume {}'.format(path)
            self._error(message)
            raise Exception(message)

    def cmd_mount(self, src, path, uuid=True, opts='subvolid=0'):
        '''
Mount a device

Arguments:
  src  = Device to mount
  path = Mountpoint
  uuid = 'src' argument is a UUID (Default True)
  opts = Mount options (Default "subvolid=0")
'''

        self._info('mounting local volume')

        self._debug('path = {}'.format(path))
        self._debug('opts = {}'.format(opts))

        if uuid:
            src = 'UUID=%s' % src

        self._debug('src = {}'.format(src))

        returncode = subprocess.call(('mount', '-o', opts, src, path))
        if returncode != 0:
            raise Exception('Mounting local filesystem failed')

        return

    def cmd_unmount(self, mountpoint):
        '''Unmount a device'''

        argv = ('umount', mountpoint)

        self._info('unmounting filesystem')

        self._debug('testing path {}'.format(mountpoint))

        if not os.path.ismount(mountpoint):
            self._warn('{} is not a mountpoint')
            return

        returncode = subprocess.call(argv)

        if returncode != 0:
            self._warn('{} was not successful'.format(' '.join(argv)))

        return


if __name__ == '__main__':
    # This is just a good idea
    os.umask(0o77)

    btrfs_backup().run()
