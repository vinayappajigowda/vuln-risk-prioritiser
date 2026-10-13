# Lab setup: getting real scan data

This project needs real scan exports. You'll scan a deliberately vulnerable virtual machine on a private network inside your laptop, so nothing outside your laptop is touched.

> **Only scan machines you own or have written permission to scan.** Scanning other people's systems can be illegal. Keep the vulnerable VM on a **host-only** network so it is never reachable from the internet or your home network.

## What you need (all free)

| Tool | Why | Where |
|---|---|---|
| VirtualBox | Runs the target VM | virtualbox.org |
| Metasploitable 2 | A deliberately vulnerable Linux VM, made for practice | sourceforge.net/projects/metasploitable |
| Nessus Essentials | Vulnerability scanner (up to 5 hosts; check the licence length when you register) | tenable.com/products/nessus/nessus-essentials |
| *or* OpenVAS / Greenbone Community Edition | Open-source scanner, if you prefer | greenbone.github.io/docs |

## 1. Set up the target VM (about 20 minutes)

1. In VirtualBox: **File > Tools > Network Manager > Host-only Networks**. Make sure one exists (usually `192.168.56.1`, with DHCP enabled).
2. Unzip Metasploitable 2. In VirtualBox click **New**, name it `metasploitable`, type **Linux / Ubuntu (32-bit)** (Metasploitable 2 is a 32-bit system; if that option is missing, pick **Other Linux (32-bit)**), give it 512 MB to 1 GB of RAM, and choose **Use an existing virtual hard disk file**, picking the `.vmdk` from the zip.
3. Open the VM's **Settings > Network > Adapter 1**, and set **Attached to: Host-only Adapter**. Don't use NAT or Bridged.
4. Start the VM and log in with `msfadmin` / `msfadmin`. Run `ifconfig` and note the IP address, for example `192.168.56.101`.
5. On Windows, open PowerShell and run `ping 192.168.56.101`. It should reply.

## 2. Install Nessus Essentials (about 20 minutes)

1. Register on the Nessus Essentials page to get a free activation code by email.
2. Download and install Nessus for Windows. It opens at `https://localhost:8834` in your browser. Accept the certificate warning, since it's your own machine.
3. Choose **Nessus Essentials**, enter the activation code, create a login, and wait for the plugins to download (this can take 30+ minutes).

## 3. Run the first scan

1. Click **New Scan > Basic Network Scan**.
2. Set **Name** to `Lab scan` and **Targets** to your Metasploitable IP.
3. Click **Save**, then **Launch**. It takes 10–30 minutes.
4. When it's done, open the scan and click **Report**. Choose **HTML** and the **Detailed Vulnerabilities By Host** template, then **Generate Report**.
   Nessus Essentials blocks the CSV and `.nessus` **Export** options, but this HTML report has everything the tool needs: CVEs, CVSS, ports, solutions, and Tenable's own EPSS and CISA KEV notes.
   Make sure you pick the *Detailed* template: the summary one has no CVEs or ports.
5. Save the file into this project as `data/scans/nessus_YYYY-MM-DD.html`, using the **scan date**, for example `nessus_2026-10-12.html`.

(If you have a Nessus edition that allows **Export**, a `.nessus` or `.csv` export works too.)

The date in the file name is how the project knows when each scan happened, so always use the real scan date.

## 4. Fix something, then rescan on a later day

This creates the "fixed" findings, time-to-fix and SLA data, which makes the project much stronger.

1. On the Metasploitable VM, stop or remove a few vulnerable services. List them with `ls /etc/init.d`. For example:
   ```bash
   sudo /etc/init.d/distcc stop
   sudo /etc/init.d/samba stop
   ```
   Note what you changed and why. This is your remediation story for interviews.
2. On a **later day**, run the same scan again in Nessus and export it as `data/scans/nessus_<that date>.csv`.
3. Ideally do three scans over a week or two: before, after the first fixes, and after more fixes.

Services you stop with `/etc/init.d` start again when the VM reboots. Either don't reboot between scans, or remove them from startup.

## 5. Optional: mark your critical assets

Copy `data/assets.example.csv` to `data/assets.csv` and edit it. Hosts marked `criticality=high` or `internet_facing=yes` get their P2 and P3 findings raised one level.

## Using OpenVAS instead

Export the results report as CSV (**Scans > Reports > Download > CSV Results**) and put it in `data/scans/`. The date is read from the report's Timestamp column, or from a date in the file name if there is one. The project reads both Nessus and OpenVAS formats.
