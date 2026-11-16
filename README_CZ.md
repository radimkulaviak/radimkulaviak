# Radim Kulaviak — Linux Infrastructure & Virtualization Consultant

**Proxmox · migrace z VMware · hardening Linuxu · zabezpečení DNS a e-mailu**

Freelance konzultant pro malé a střední firmy v ČR, SR a EU (včetně DACH, na dálku).
Provozuji produkční Linux hosting **přes 25 let** — vlastní platforma [isol.cz](https://www.isol.cz) obsluhuje ~320 webhostingových klientů, ~360 MariaDB databází a DNS pro ~250 domén na Apache, MariaDB, Postfix, Dovecot, BIND a PHP-FPM.

## Praktické zkušenosti (vlastní produkční platforma)
- **Hostingový stack:** ~320 webhostingových klientů (PHP/HTML), ~360 MariaDB databází (většinou InnoDB), DNS pro ~250 domén, mail (Postfix, Dovecot, Amavis, OpenDKIM).
- **PHP:** verze 5.6 až 8.4 vedle sebe, izolace PHP-FPM poolů po doménách.
- **Zabezpečení mailu a DNS:** hromadné audity SPF/DKIM/DMARC/DNSBL a hromadné nasazení OpenDKIM; úklid BINDu (~1 500 osiřelých zón).
- **Řešení incidentů:** napadené weby (odstranění webshellů/backdoorů), phishing rozesílaný přes napadený PHP skript, sledování BEC podvodů.
- **Migrace platformy:** celý stack z CentOS 6 na Ubuntu 24 (vhosty Apache, MySQL uživatelé a kódování, DNS zóny).
- **Virtualizace:** 3-uzlový Proxmox VE + Ceph HA cluster v labu, včetně testů výpadků.

## Co nabízím
1. **Migrace VMware → Proxmox** — posouzení, plán, provedení, ověření (Linux i Windows hosté).
2. **Upgrade legacy Linuxu** — CentOS / EOL systémy na Ubuntu 24.04 LTS paralelním buildem a řízeným přepnutím (web, mail, DB, DNS).
3. **Bezpečnostní hardening** — SSH, firewall, fail2ban, TLS, patching, audit s reportem před/po (Lynis).
4. **Revize zabezpečení DNS a e-mailu** — DNSSEC, SPF/DKIM/DMARC, CAA, zónové transfery, open resolver; technická analýza mezer ve vztahu k NIS2 (nejde o právní poradenství).
5. **Proxmox HA clustery** — Ceph, návrh kvora, testování výpadků.

## Repozitáře
- [linux-hardening-baseline](https://github.com/radimkulaviak/linux-hardening-baseline) — Ansible základ pro Ubuntu 24.04 + Lynis před/po.
- [legacy-centos-to-ubuntu-migration](https://github.com/radimkulaviak/legacy-centos-to-ubuntu-migration) — metodika, read-only inventarizační skript, checklist přepnutí.
- [dns-mail-security-audit](https://github.com/radimkulaviak/dns-mail-security-audit) — hromadný audit DNS/mailu (výstup CSV).
- [vmware-to-proxmox-migration](https://github.com/radimkulaviak/vmware-to-proxmox-migration) — migrační playbook, ověřeno v labu.
- [proxmox-ceph-ha-cluster](https://github.com/radimkulaviak/proxmox-ceph-ha-cluster) — report testu výpadků 3-uzlového Proxmox/Ceph/Galera.
- [production-cicd-ubuntu-stack](https://github.com/radimkulaviak/production-cicd-ubuntu-stack) — nasazení přes GitHub Actions a SSH s releasy, health checkem a rollbackem.

## Transparentnost
Repozitáře dokumentují práci na **mých vlastních produkčních a testovacích systémech**. Skripty jsou ukázky; nejdřív je vyzkoušejte v neprodukčním prostředí.

## Aktuálně se učím
AWS (Solutions Architect Associate, SAA-C03). Produkční zkušenost s AWS zatím nemám — moje praxe je v self-hosted a on-premise infrastruktuře.

**Kontakt:** https://www.isol.cz/kontakt.html
