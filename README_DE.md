# Radim Kulaviak — Linux Infrastructure & Virtualization Consultant

**Proxmox · VMware-Migration · Linux-Härtung · DNS- und Mail-Sicherheit**

Freiberuflicher Berater für kleine und mittlere Unternehmen in Tschechien, der Slowakei und der EU (inkl. DACH, remote).
Seit **über 25 Jahren** betreibe ich Linux-Hosting in Produktion — meine eigene Plattform [isol.cz](https://www.isol.cz) betreut ~320 Webhosting-Kunden, ~360 MariaDB-Datenbanken und DNS für ~250 Domains mit Apache, MariaDB, Postfix, Dovecot, BIND und PHP-FPM.

## Praxiserfahrung (eigene Produktionsplattform)
- **Hosting-Stack:** ~320 Webhosting-Kunden (PHP/HTML), ~360 MariaDB-Datenbanken (überwiegend InnoDB), DNS für ~250 Domains, Mail (Postfix, Dovecot, Amavis, OpenDKIM).
- **PHP:** Versionen 5.6 bis 8.4 parallel, mit PHP-FPM-Pool-Isolation pro Domain.
- **Mail-/DNS-Sicherheit:** Massenaudits SPF/DKIM/DMARC/DNSBL und OpenDKIM-Rollout; BIND-Bereinigung von ~1.500 verwaisten Zonen.
- **Incident Response:** kompromittierte Kundenseiten (Webshell-/Backdoor-Entfernung), Phishing über ein gehacktes PHP-Skript, Überwachung von BEC-Betrug.
- **Plattformmigration:** kompletter Stack von CentOS 6 auf Ubuntu 24 (Apache-vHosts, MySQL-Benutzer und Zeichensätze, DNS-Zonen).
- **Virtualisierung:** 3-Knoten Proxmox VE + Ceph HA-Cluster im Labor mit Ausfalltests.

## Mein Angebot
1. **VMware → Proxmox Migration** — Assessment, Migrationsplan, Durchführung, Verifikation (Linux- und Windows-Gäste).
2. **Upgrade von Legacy-Linux** — CentOS / EOL-Systeme auf Ubuntu 24.04 LTS per Parallelaufbau und kontrolliertem Cutover (Web, Mail, DB, DNS).
3. **Sicherheitshärtung** — SSH, Firewall, fail2ban, TLS, Patching, Audit mit Vorher/Nachher-Bericht (Lynis).
4. **DNS- und Mail-Sicherheitsprüfung** — DNSSEC, SPF/DKIM/DMARC, CAA, Zonentransfers, Open Resolver; technische Lückenanalyse mit NIS2-Bezug (keine Rechtsberatung).
5. **Proxmox-HA-Cluster** — Ceph, Quorum-Design, Ausfalltests.

## Repositories
- [linux-hardening-baseline](https://github.com/radimkulaviak/linux-hardening-baseline) — Ansible-Basis für Ubuntu 24.04 + Lynis vorher/nachher.
- [legacy-centos-to-ubuntu-migration](https://github.com/radimkulaviak/legacy-centos-to-ubuntu-migration) — Vorgehen, Read-only-Inventarskript, Cutover-Checkliste.
- [dns-mail-security-audit](https://github.com/radimkulaviak/dns-mail-security-audit) — DNS-/Mail-Massenaudit (CSV-Ausgabe).
- [vmware-to-proxmox-migration](https://github.com/radimkulaviak/vmware-to-proxmox-migration) — Migrations-Playbook, im Labor getestet.
- [proxmox-ceph-ha-cluster](https://github.com/radimkulaviak/proxmox-ceph-ha-cluster) — Ausfalltest-Bericht: 3-Knoten Proxmox/Ceph/Galera.
- [production-cicd-ubuntu-stack](https://github.com/radimkulaviak/production-cicd-ubuntu-stack) — Deployment per GitHub Actions und SSH mit Releases, Health-Check und Rollback.

## Transparenz
Die Repositories dokumentieren Arbeit an **meinen eigenen Produktions- und Testsystemen**. Die Skripte sind Beispiele; bitte zuerst in einer Nicht-Produktivumgebung testen.

## Aktuell in Weiterbildung
AWS (Solutions Architect Associate, SAA-C03). Noch keine Produktionserfahrung mit AWS — mein Hintergrund ist Self-Hosted- und On-Premises-Infrastruktur.

**Kontakt:** https://www.isol.cz/kontakt.html
