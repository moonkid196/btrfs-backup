#!/usr/bin/env python3

import argparse
from bbcolor import bbcolor
import collections
import json
import os
import os.path
import time
import subprocess
import socket
import sys
import tempfile
from urllib.parse import urlparse
import uuid

qflag = not sys.stdout.isatty()

class btrfs_backup:

    # Global variables/defaults
    HOME        = '/var/lib/btrfs-backup'
    DATE        = time.localtime()
    CONFIGFILE  = HOME + '/config'
    CONF        = None
    qflag       = not sys.stdout.isatty()
    msgpre      = bbcolor().format('+', foreground=21, style='normal')

    COLOR_DEFAULT = 250
    COLOR_ERROR   = 160
    COLOR_WARN    = 172
    COLOR_VALUE   = 48

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

        self.bbc = bbcolor(quiet=True)
        self.msgpre = bbc.format('+', foreground=21, style='normal')
        if os.getuid() != 0:
            self.COLOR_DEFAULT = None
            self.bbc.set_fg(self.COLOR_DEFAULT)
        else:
            self.COLOR_DEFAULT = None
            self.bbc.set_fg(self.COLOR_DEFAULT)
            self.bbc.set_style('bold')
        return

    def pr(self, msg, file=sys.stdout, bbc=None):
        '''Method to print a standard status message'''

        if bbc is None:
            bbc = self.bbc

        if not self.qflag:
            print(self.msgpre, bbc.format(msg), file=file)
        return

    def parseargs(self, args):
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

        parser.add_argument('-f', dest='file', default=CONFIGFILE, nargs=1, \
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

        self.args = parser.parse_args(args)

        if self.args.quiet:
            self.qflag = True

        if self.args.verbose:
            self.qflag = False

        self.CONFIGFILE = self.args.file[0]

        return

    def turn_root(self, argv):
        '''Function to make sure we run as root'''

        args = []

        # Check if we're already root
        if os.getuid() == 0:
            return

        self.pr('Changing to root')

        args.extend(argv)
        args.insert(0, 'sudo')
        returncode = subprocess.call(args)

        if returncode != 0:
            raise Exception('Privileged process exited non-zero (%d)' % returncode)

        self.pr('Exited from privileged process')
        raise self.__class__.PrivilegedExit

    def parseconfig(self):
        # For easier reference
        CONFIGFILE = self.CONFIGFILE

        self.pr('Parsing %s' % CONFIGFILE)
        CONFIGFILE = os.path.abspath(CONFIGFILE)
        CONFIGFILE = os.path.realpath(CONFIGFILE)
        self.CONFIGFILE = CONFIGFILE

        self.pr('Using %s' % CONFIGFILE)

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
            raise Exception('%s: Could not load config file, %s' % \
                (e, CONFIGFILE))

        else:
            os.environ['HOME'] = self.CONF['dirs']['home']

    def run(self):
        '''Method to execute the command given'''

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
        for uuid in self.CONF['backups'].keys():
            uri  = self.CONF['backups'][uuid]['uri']
            print(self.bbc.format('UUID:'), self.bbc.format(uuid, foreground=self.COLOR_VALUE))
            print(self.bbc.format('    URI:'), self.bbc.format(uri, foreground=self.COLOR_VALUE))

    def snapshot(self, uuid):
        '''Snapshot all local disks'''

        # Easier referencing
        dirs = self.CONF['dirs']
        uuid = str(uuid)

        if uuid not in self.CONF['backups']:
            raise Exception('UUID %s not a valid backup id' % uuid)

        backup = self.CONF['backups'][uuid]

        self.pr('Snapshotting backup with id %s' % uuid)

        self.cmd_mount(backup['localuuid'], dirs['self'])

        try:
            for vol in backup['volumes']:
                self.pr('Snapshotting subvolume %s at %s' % (vol, self.DATE))
                path = os.path.join(dirs['self'], vol)
                snap = '%s-%s' % (path, self.DATE)

                self.btrfs_snapshot(path, snap)

        except:
            raise

        finally:
            self.cmd_unmount(dirs['self'])
        return

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
        # Confirm that snapshot and subvolume are on the same device
        dir0 = os.path.dirname(path)
        dir1 = os.path.dirname(snap)
        if os.lstat(dir0).st_dev != os.lstat(dir1).st_dev:
            raise Exception('%s and %s wouldn\'t be on the same device')

        returncode = subprocess.call(
            ('btrfs', 'subvolume', 'snapshot', '-r', path, snap), \
            stdout=subprocess.DEVNULL)

        if returncode != 0:
            raise Exception('Failed to snapshot volume %s' % path)

        return

    def cmd_mount(self, src, path, uuid=True, opts='subvolid=0'):
        '''
Mount a device

Arguments:
  src  = Device to mount
  path = Mountpoint
  uuid = 'src' argument is a UUID (Default True)
  opts = Mount options (Default "subvolid=0")
'''

        if uuid:
            src = 'UUID=%s' % src

        returncode = subprocess.call(('mount', '-o', opts, src, path))
        if returncode != 0:
            raise Exception('Mounting local filesystem failed')

        return

    def cmd_unmount(self, mountpoint):
        '''Unmount a device'''

        if not os.path.ismount(mountpoint):
            raise Exception('%s is not a mount point' % mountpoint)

        returncode = subprocess.call(('umount', mountpoint))
        if returncode != 0:
            raise Exception('Failed to unmount %s' % mountpoint)

        return


if __name__ == '__main__':
    bbc = bbcolor(quiet=True)
    msgpre = bbc.format('+', foreground=21, style='normal')
    if os.getuid() == 0:
        bbc.set_style('bold')

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
            print(msgpre, bbc.format('Exiting'))
        raise SystemExit(0) from e

    except Exception as e:
        if not qflag:
            bbc.pr('+ Got Exception "%s"' % e.__class__.__name__)
        bbc.pr('ERROR: %s' % str(e), foreground=160)
        raise SystemExit(1)
