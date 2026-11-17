**English** | [Deutsch](README.de.md) | [Čeština](README.cs.md)

# Security Audit & Hardening of a Production Shared-Hosting Server

Case study: an audit and hardening of a live multi-tenant LAMP + mail server, with the outages it caused and how they were fixed. All identifying data is anonymized: IPs use RFC 5737 documentation ranges, and hostnames, client domains and ports are generalized.

## Environment

| Item | Value |
| --- | --- |
| OS | Ubuntu 24.04 LTS, kernel 6.8 |
| Workload | Shared web hosting, 350+ client sites, 280+ MariaDB databases, authoritative DNS for 240+ domains |
| Stack | Apache 2.4 + ModSecurity, PHP-FPM (multiple versions, per-site pools), MariaDB 10.11, Postfix, Dovecot, Amavis/SpamAssassin/ClamAV, BIND 9, ProFTPD, fail2ban |
| Extras | Incus containers (one GUI workload behind VNC), Nagios + NRPE |
| Constraints | Production box, no maintenance window, legacy PHP versions that cannot be removed |

## Approach

1. **External view.** Port scan of all public IPs from outside the network (`nmap`, PowerShell `Test-NetConnection` from a residential connection), plus DNS checks: open recursion and AXFR.
2. **Internal view.** `ss -tulpn` to see what actually listens on public interfaces, compared with the scan.
3. **Host audit.** Lynis 3.1.7 baseline: hardening index **77**, 0 warnings, 39 suggestions.
4. **Remediate in small, reversible steps**, verifying each one from the outside.

One early lesson: running `nmap` against the server's own hostname from the server itself resolved via `/etc/hosts` to `127.0.0.1`. That showed localhost-only services (Amavis, Postfix re-injection ports), so it was not a valid external view.

## Findings

| # | Finding | Risk | Status |
| --- | --- | --- | --- |
| 1 | iptables `INPUT` policy `ACCEPT`: any new listener on `0.0.0.0` became public | High | Root cause identified, default-deny planned |
| 2 | MariaDB 3306 reachable from the Internet | High | Fixed: bound to `127.0.0.1` |
| 3 | VNC (2 ports) and SFTP into a container exposed via Incus proxy devices on `0.0.0.0`; only one port had an IP allow-rule | High | Fixed: duplicate proxy removed, remaining ports restricted to admin IP |
| 4 | NRPE 5666 public (monitoring server is local) | Medium | Fixed: `server_address=127.0.0.1` |
| 5 | rpcbind 111 public, NFS unused | Medium | Fixed: service disabled |
| 6 | xrdp installed and enabled, unused | Medium | Fixed: purged |
| 7 | Certbot renewals used `pre_hook = systemctl stop apache2` on 113 certificates | Availability | Fixed: shared webroot, no stop/start |
| 8 | Stale `/etc/hosts` entry pointing to a released IP | Low | Fixed |
| 9 | Kernel/sysctl, unused protocols, core dumps, process accounting, etc. (Lynis) | Low | Partly fixed (index 77 → 82) |
| 10 | DNS open resolver | — | Not vulnerable: recursion `REFUSED` from outside, AXFR refused |

## Remediation highlights

### Incus proxy devices bound to localhost / admin IP

```bash
incus config device remove <ct> vnc-dup
incus config device set <ct> sftp-port listen tcp:127.0.0.1:2223
# admin access via SSH tunnel, or an explicit allow-rule:
iptables -I INPUT 1 -s 198.51.100.7/32 -p tcp --dport 5901 -j ACCEPT
iptables -I INPUT 2 -p tcp --dport 5901 -j DROP
```

### MariaDB local only

```bash
ss -tn state established '( sport = :3306 )'      # confirm no remote clients first
sed -i 's/^\s*bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mariadb.conf.d/50-server.cnf
systemctl restart mariadb
```

### Certbot without downtime

Certbot used `standalone` or stop/start hooks, so Apache went down on every renewal run. If a renewal hung, the sites stayed down. The fix is a single shared ACME webroot for all vhosts, with no hooks:

```apache
# /etc/apache2/conf-available/acme-webroot.conf
Alias /.well-known/acme-challenge/ /var/www/letsencrypt/.well-known/acme-challenge/
<Directory "/var/www/letsencrypt/.well-known/acme-challenge/">
    Options None
    AllowOverride None
    Require all granted
</Directory>
```

```bash
sed -i '/^pre_hook = systemctl stop apache2/d; /^post_hook = systemctl start apache2/d' /etc/letsencrypt/renewal/*.conf
certbot renew --webroot -w /var/www/letsencrypt --deploy-hook "systemctl reload apache2"
```

A parallel `curl` check against every SAN of every certificate found certificates for domains hosted elsewhere or pointing at a released IP. Those are scheduled for deletion.

### Default-deny firewall with automatic rollback (planned)

```bash
iptables-save > /root/iptables.bak; ip6tables-save > /root/ip6tables.bak
nohup sh -c 'sleep 300; iptables-restore < /root/iptables.bak; ip6tables-restore < /root/ip6tables.bak' &
# allow lo, ESTABLISHED/RELATED, container bridge, and the hosting service ports, then:
iptables -P INPUT DROP; ip6tables -P INPUT DROP
# verify from a second session, then kill the rollback job and persist
```

### Host hardening (Lynis 77 → 82)

- sysctl: `kptr_restrict`, `sysrq`, `unprivileged_bpf_disabled`, `bpf_jit_harden`, `suid_dumpable`, `protected_fifos`, martian logging, ICMP redirects. `ip_forward` and `rp_filter` stay unchanged because of the container networking.
- Blacklisted unused protocols (`dccp`, `sctp`, `rds`, `tipc`) and `usb-storage`
- Core dumps disabled, sysstat and debsums cron enabled, stale `rc` packages purged
- AIDE: the distribution config produced an empty database (`Number of entries: 0`), so a standalone config covering `/boot /etc /usr /root/.ssh` was added, with a daily check that mails on change

Deliberately skipped on a production host: separate partitions, GRUB password, global `umask 027`, `hidepid`, and global `allow_url_fopen=Off`.

## Incidents during the work (and what they taught)

| Incident | Root cause | Fix | Lesson |
| --- | --- | --- | --- |
| Apache down (`Address already in use :80`) | Certbot in standalone mode hung on port 80 during a timer run after `pre_hook` had stopped Apache | Killed certbot, moved to the shared webroot | Never let a renewal job own the web server's lifecycle |
| MariaDB would not start after a config change | `/tmp` had lost its `1777` mode, so InnoDB could not create temp files | `chmod 1777 /tmp` | A restart exposes latent breakage. Check the base filesystem before blaming the change |
| Load average ~1 → 4–6, services failing | A SpamAssassin training script copied ~187k mails (52 GB) into a temp dir. Its `-ctime` filter matched far more than intended, it had no cleanup on failure, and it filled `/`. A container's rsyslog then looped on write errors at ~35k lines/min | Deleted temp data, rewrote the script, capped container journald | Temp-heavy jobs need a free-space check, `trap` cleanup, `-mtime` rather than `-ctime`, and a target volume that isn't `/` |
| High MariaDB CPU from one e-commerce site | Unindexed `WHERE` on a 117k-row product table, hit several times per second | `ALTER TABLE ... ADD INDEX` | Check `SHOW PROCESSLIST` before tuning the server |

### Rewritten training script (core)

```bash
LIST=$(mktemp "$BASE/list.XXXXXX"); T=$(mktemp -d "$BASE/satrain.XXXXXX")
trap 'rm -rf -- "$T" "$LIST"' EXIT INT TERM
# ... build NUL-separated list with -mtime -N -size -512k, print per-folder counts ...
[ $((MB + 2048)) -gt "$FREE" ] && { echo "not enough space"; exit 1; }
pv -0 -l -s "$N" < "$LIST" | xargs -0 -r cp --backup=numbered -t "$T"
chown -R amavis "$T"
nice -n 19 ionice -c3 sudo -u amavis -H sa-learn --"$MODE" --progress "$T"
```

Result: the Bayes database went from a 20:1 spam/ham ratio (23,933 / 1,169) to 1.8:1 (23,933 / 13,363) after learning ~12k legitimate sent messages from 300 days of mail.

## Results

- Internet-exposed internal services: **5 → 0** (MariaDB, NRPE, rpcbind, duplicate VNC, unrestricted SFTP)
- Container admin ports restricted to a single admin IP
- Lynis hardening index **77 → 82**, 0 warnings
- Certificate renewal no longer causes web downtime
- Disk-full incident traced end-to-end and prevented from recurring

## Open recommendations

1. Switch the firewall to default-deny (procedure above).
2. Mitigate legacy PHP versions: per-pool `disable_functions`, `open_basedir`, `allow_url_fopen` per pool.
3. Move ModSecurity from `DetectionOnly` to `On` after reviewing false positives.
4. Dovecot: `disable_plaintext_auth = yes`, `ssl = required`.
5. Default vhost on bare IP returns 403, not the distribution page.
6. Monitoring alerts for disk usage and certificate expiry, since renewal is now manual.

## Tools

`nmap`, `ss`, `Test-NetConnection`, `Resolve-DnsName`, Lynis, AIDE, fail2ban, iptables/ip6tables, Incus, certbot, MariaDB `PROCESSLIST`, `htop`, `journalctl`, `pv`, `sa-learn`.
