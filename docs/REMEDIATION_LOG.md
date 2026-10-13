# Remediation log

Lab target: Metasploitable 2 (192.168.56.103), isolated host-only network.
Baseline scan: 2026-10-12 (Nessus Essentials, Basic Network Scan).

I worked from the tool's fix-first list. I picked the P1/P2 findings that could be fixed with a configuration change, and checked every fix by testing the port from another machine before rescanning.

| Date | Finding | Priority and why | Port | Fix | Checked |
|---|---|---|---|---|---|
| 2026-10-13 | Apache Tomcat AJP "Ghostcat" (CVE-2020-1938) | P1: in CISA KEV, EPSS 99% | 8009/tcp | Commented out the AJP connector in `/etc/tomcat5.5/server.xml` (backed up first), then restarted Tomcat | Port closed |
| 2026-10-13 | Bind Shell Backdoor | P2: critical, no CVE, so manual review (it's a root shell) | 1524/tcp | Disabled the `ingreslock` entry in `/etc/inetd.conf`, then restarted xinetd | Port closed |
| 2026-10-13 | Unencrypted Telnet, rlogin, rsh, rexec | P1/P2 depending on the finding | 23, 512, 513, 514/tcp | Disabled in `/etc/inetd.conf`, then restarted xinetd | Port closed |
| 2026-10-13 | VNC server with the password "password" | P2: critical, no CVE, so manual review | 5900/tcp | Stopped the VNC server process | Port closed |

**Rescan on 2026-10-13 confirmed 6 findings fixed:** Ghostcat, the bind-shell backdoor, VNC, rlogin, Telnet, and an exposed X server (port 6000). The X server was a side effect of stopping VNC, because the VNC server was also running the X display.

## What I learned

- **Verify every fix.** After I edited `/etc/inetd.conf`, ports 1524, 23 and 513 were *still open*. `netstat -tlnp` showed they were served by **xinetd** (running in inetd-compatibility mode), not inetd, so restarting inetd changed nothing. Restarting xinetd closed them. Without the port test I would have reported these as fixed when they weren't.
- **Turn off what isn't needed.** Most of these were legacy services that shouldn't be running at all. Disabling a service removes the risk completely, and it's quicker than patching it.
- **Stopping a process isn't a permanent fix.** Killing the VNC process doesn't survive a reboot. In a real environment I'd remove it from startup or uninstall it, and track it until the rescan confirms the fix.
- **Still open and accepted for now:** old TLS/SSL settings on SMTP and PostgreSQL, Samba Badlock, and the end-of-life OS. These need software upgrades that this deliberately vulnerable VM can't take. In a real environment they'd get a risk exception with an owner and a review date.
