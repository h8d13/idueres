# IDUERES

> Helps to find application artifact locations, parse and dry-run deletes.

> This is made for apps that do not have self clean-up in `.install` files (`pre_remove` / `post_remove`)

## Setup

Requires: `python-audit` `audit`

`auditctl -s` should show enabled=1 

Needs rule (one-time, before running):

`sudo auditctl -a always,exit -F arch=b64 -S execve -S execveat -k pkgtrace`

Revert (remove the rule when done):

`sudo auditctl -D -k pkgtrace`

## Running

1. `sudo pkgtrace.py --history /tmp/pkgtrace.tsv`

Use any app like you normally would. This records all writes.

2. `sudo storeparser.py --input /tmp/pkgtrace.tsv` 

This creates/appends `/var/lib/pkgtrace/db.json` by application/write locations.

3. `sudo sweep.py -n chromium`

This returns:
```
# chromium
  would rm  /home/user/.config/chromium (10.0 MiB, 78 writes)
  would rm  /home/user/.cache/chromium (2.6 MiB, 37 writes)
  would rm  /home/user/.cache/nvidia (3.2 MiB, 2 writes)
```

Finally: `sudo ./sweep.py chromium` would actually delete these things. Finally you can remove the app normally with you prefered `pacman` flags.