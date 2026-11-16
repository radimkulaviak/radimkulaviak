# Radim Kulaviak — Linux Infrastructure & Virtualization Consultant

**Proxmox · VMware migration · Linux hardening · DNS & mail security**

Freelance consultant for small and medium-sized businesses in the Czech Republic, Slovakia and the wider EU (DACH included, remote).
I have been running production Linux hosting for **25+ years** — my own platform [isol.cz](https://www.isol.cz) serves ~320 web hosting clients, ~360 MariaDB databases and DNS for ~250 domains on Apache, MariaDB, Postfix, Dovecot, BIND and PHP-FPM.

## Hands-on experience (own production platform)
- **Hosting stack:** ~320 web hosting clients (PHP/HTML), ~360 MariaDB databases (mostly InnoDB), DNS for ~250 domains, mail (Postfix, Dovecot, Amavis, OpenDKIM).
- **PHP:** versions 5.6 to 8.4 side by side, with per-domain PHP-FPM pool isolation.
- **Mail/DNS security:** bulk SPF/DKIM/DMARC/DNSBL auditing and bulk OpenDKIM rollout; BIND cleanup of ~1,500 orphaned zones.
- **Incident response:** compromised hosted sites (webshell/backdoor removal), phishing sent via a hacked PHP script, BEC fraud monitoring.
- **Platform migration:** full stack from CentOS 6 to Ubuntu 24 (Apache vhosts, MySQL users and charsets, DNS zones).
- **Virtualization:** 3-node Proxmox VE + Ceph HA cluster in my lab, with failure testing.

## What I offer
1. **VMware → Proxmox migration** — assessment, migration plan, execution, verification (Linux and Windows guests).
2. **Legacy Linux upgrade** — CentOS / EOL systems to Ubuntu 24.04 LTS via parallel build and controlled cutover (web, mail, DB, DNS).
3. **Security hardening** — SSH, firewall, fail2ban, TLS, patching, audit with before/after report (Lynis).
4. **DNS & mail security review** — DNSSEC, SPF/DKIM/DMARC, CAA, zone transfers, open resolvers; NIS2-oriented technical gap review (not legal advice).
5. **Proxmox HA clusters** — Ceph storage, quorum design, failure testing.

## Repositories
- [linux-hardening-baseline](https://github.com/radimkulaviak/linux-hardening-baseline) — Ansible baseline for Ubuntu 24.04 + Lynis before/after.
- [legacy-centos-to-ubuntu-migration](https://github.com/radimkulaviak/legacy-centos-to-ubuntu-migration) — migration method, read-only inventory script, cutover checklist.
- [dns-mail-security-audit](https://github.com/radimkulaviak/dns-mail-security-audit) — bulk DNS/mail audit script (CSV output).
- [vmware-to-proxmox-migration](https://github.com/radimkulaviak/vmware-to-proxmox-migration) — migration playbook, tested in lab.
- [proxmox-ceph-ha-cluster](https://github.com/radimkulaviak/proxmox-ceph-ha-cluster) — 3-node Proxmox/Ceph/Galera failure test report.
- [production-cicd-ubuntu-stack](https://github.com/radimkulaviak/production-cicd-ubuntu-stack) — GitHub Actions SSH deployment with releases, health check and rollback.

## Transparency
The repositories document work done on my **own production and lab systems**. Scripts are examples; test them in a non-production environment first.

## Currently learning
AWS (Solutions Architect Associate, SAA-C03). No production AWS experience yet — my background is self-hosted and on-premises infrastructure.

**Contact:** https://www.isol.cz/kontakt.html
