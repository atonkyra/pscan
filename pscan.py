#!/usr/bin/python
from os import listdir
from os.path import isfile, join, isdir
import re
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

class Flags:
    PARANOID=False

# - utils - #
def get_cmdline(pid):
    fh = open('/proc/%s/cmdline' % (pid))
    cmdline = fh.read().strip()
    fh.close()
    return cmdline
# - end utils - #

# - signatures - #
map_scanners = []

def s00001_executable_untrusted_deleted_handles(pid, data):
    trusted_paths = ['/usr/lib/','/usr/lib64/','/usr/bin/','/usr/sbin/','/lib/','/lib64/','/bin/','/sbin/','/lib32/','[vdso]']
    # filters out non-executable maps and executable memory area, also empty (deleted) handles aren't supported
    if 'x' not in data[1] or data[4] == "0" or data[-1] == '(deleted)':
        return
    for trusted_path in trusted_paths:
        if data[-1].startswith(trusted_path):
            if Flags.PARANOID:
                continue
            else:
                return
    if re.search(r'\.nfs[0-9a-f]+',data[-1],re.I) is not None:
        logger.error("[pid=%s, cmdline=%s] deleted executable NFS handle: %s" % (pid, get_cmdline(pid), data[-1]))
    elif '(deleted)' in data[-1]:
        logger.error("[pid=%s, cmdline=%s] deleted executable FILE handle: %s" % (pid, get_cmdline(pid), data[-1]))
map_scanners.append(s00001_executable_untrusted_deleted_handles)

# - end signatures - #

def get_maps(pid):
    mapdata = []
    try:
        mapfh = open('/proc/%s/maps' % (pid), 'r')
        mapdata = [ d.strip().split(None, 5) for d in mapfh.readlines() ]
        mapfh.close()
    except IOError:
        pass
    return mapdata

def scan_map_entry(pid, entry):
    for map_scanner in map_scanners:
        map_scanner(pid, entry)

pids = [ h for h in listdir('/proc') if isdir('/proc/%s' % (h)) and re.match(r'^[0-9]+$', h) ]
num_pids = len(pids)
cur_idx = 0
for pid in pids:
    if cur_idx % 1000 == 0:
        logger.info("scanning... progress: %i/%i" % (cur_idx, num_pids))
    maps = get_maps(pid)
    for entry in maps:
        scan_map_entry(pid, entry)
    cur_idx += 1
logger.info("scan complete")

