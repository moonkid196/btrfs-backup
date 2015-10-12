### TODO

- Generate requirements list (RPMs)
- Need to decide if we keep state on-disk or not
- Add in hourly job to wake up script and snapshot, etc
- Prune remote backups/snapshots
- Time job-transfers to stop early, if needed
- More error-checking in functions
- More usage modes (mount-only, udisks integration, et al)
- Initialization
- Make into a service
- Test usb, nfs operation
- Critical threshold of local snapshots, where it starts skipping over some to better catch up.
- Always-on vs. intermittent operation (to configure the systemd.timer)
- Randomization of timer activation min:sec when using calendar time
