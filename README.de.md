[English](README.md) | **Deutsch** | [Čeština](README.cs.md)

# Sicherheitsaudit und Härtung eines produktiven Shared-Hosting-Servers

Fallstudie: Audit und Härtung eines laufenden Multi-Tenant-LAMP- und Mailservers, einschließlich der dabei verursachten Ausfälle und ihrer Behebung. Alle identifizierenden Daten sind anonymisiert: IP-Adressen stammen aus den Dokumentationsbereichen nach RFC 5737, Hostnamen, Kundendomains und Ports sind verallgemeinert.

## Umgebung

| Punkt | Wert |
| --- | --- |
| Betriebssystem | Ubuntu 24.04 LTS, Kernel 6.8 |
| Last | Shared Hosting, 350+ Kundenwebsites, 280+ MariaDB-Datenbanken, autoritatives DNS für 240+ Domains |
| Stack | Apache 2.4 + ModSecurity, PHP-FPM (mehrere Versionen, Pool pro Website), MariaDB 10.11, Postfix, Dovecot, Amavis/SpamAssassin/ClamAV, BIND 9, ProFTPD, fail2ban |
| Zusätzlich | Incus-Container (eine GUI-Anwendung hinter VNC), Nagios + NRPE |
| Randbedingungen | Produktivsystem ohne Wartungsfenster, ältere PHP-Versionen, die nicht entfernt werden können |

## Vorgehen

1. **Sicht von außen.** Portscan aller öffentlichen IP-Adressen von außerhalb des Netzes (`nmap`, PowerShell `Test-NetConnection` über einen privaten Anschluss) sowie DNS-Prüfungen: offene Rekursion und AXFR.
2. **Sicht von innen.** `ss -tulpn` zeigt, was tatsächlich auf öffentlichen Schnittstellen lauscht. Das Ergebnis wurde mit dem Scan verglichen.
3. **Host-Audit.** Lynis 3.1.7 als Ausgangsbasis: Härtungsindex **77**, 0 Warnungen, 39 Empfehlungen.
4. **Behebung in kleinen, umkehrbaren Schritten**, jeder Schritt wurde von außen überprüft.

Eine frühe Erkenntnis: Ein `nmap`-Scan auf den eigenen Hostnamen vom Server selbst wurde über `/etc/hosts` zu `127.0.0.1` aufgelöst. Er zeigte nur lokal erreichbare Dienste (Amavis, Postfix-Reinjection-Ports) und war deshalb keine gültige Außensicht.

## Befunde

| # | Befund | Risiko | Status |
| --- | --- | --- | --- |
| 1 | iptables-`INPUT`-Policy `ACCEPT`: jeder neue Listener auf `0.0.0.0` wurde öffentlich | Hoch | Ursache identifiziert, Default-Deny geplant |
| 2 | MariaDB 3306 aus dem Internet erreichbar | Hoch | Behoben: an `127.0.0.1` gebunden |
| 3 | VNC (2 Ports) und SFTP in einen Container über Incus-Proxy-Devices auf `0.0.0.0` erreichbar, nur ein Port hatte eine IP-Freigaberegel | Hoch | Behoben: doppelten Proxy entfernt, übrige Ports auf Admin-IP beschränkt |
| 4 | NRPE 5666 öffentlich (Monitoring-Server ist lokal) | Mittel | Behoben: `server_address=127.0.0.1` |
| 5 | rpcbind 111 öffentlich, NFS nicht genutzt | Mittel | Behoben: Dienst deaktiviert |
| 6 | xrdp installiert und aktiv, nicht genutzt | Mittel | Behoben: entfernt |
| 7 | Certbot-Erneuerungen nutzten `pre_hook = systemctl stop apache2` bei 113 Zertifikaten | Verfügbarkeit | Behoben: gemeinsamer Webroot, kein Stop/Start |
| 8 | Veralteter Eintrag in `/etc/hosts` mit einer freigegebenen IP | Niedrig | Behoben |
| 9 | Kernel/sysctl, ungenutzte Protokolle, Core Dumps, Prozessprotokollierung usw. (Lynis) | Niedrig | Teilweise behoben (Index 77 → 82) |
| 10 | Offener DNS-Resolver | — | Nicht verwundbar: Rekursion von außen `REFUSED`, AXFR abgelehnt |

## Wichtigste Maßnahmen

### Incus-Proxy-Devices nur auf localhost / Admin-IP

```bash
incus config device remove <ct> vnc-dup
incus config device set <ct> sftp-port listen tcp:127.0.0.1:2223
# Admin-Zugriff per SSH-Tunnel oder mit expliziter Freigaberegel:
iptables -I INPUT 1 -s 198.51.100.7/32 -p tcp --dport 5901 -j ACCEPT
iptables -I INPUT 2 -p tcp --dport 5901 -j DROP
```

### MariaDB nur lokal

```bash
ss -tn state established '( sport = :3306 )'      # zuerst prüfen, dass keine entfernten Clients verbunden sind
sed -i 's/^\s*bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mariadb.conf.d/50-server.cnf
systemctl restart mariadb
```

### Certbot ohne Ausfall

Certbot nutzte den Modus `standalone` oder Stop/Start-Hooks, sodass Apache bei jedem Erneuerungslauf herunterfuhr. Hing eine Erneuerung, blieben die Websites offline. Die Lösung ist ein gemeinsamer ACME-Webroot für alle vhosts, ohne Hooks:

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

Eine parallele `curl`-Prüfung aller SANs aller Zertifikate fand Zertifikate für Domains, die anderswo gehostet werden oder auf eine freigegebene IP zeigen. Sie sind zur Löschung vorgesehen.

### Default-Deny-Firewall mit automatischem Rollback (geplant)

```bash
iptables-save > /root/iptables.bak; ip6tables-save > /root/ip6tables.bak
nohup sh -c 'sleep 300; iptables-restore < /root/iptables.bak; ip6tables-restore < /root/ip6tables.bak' &
# lo, ESTABLISHED/RELATED, Container-Bridge und Hosting-Ports freigeben, dann:
iptables -P INPUT DROP; ip6tables -P INPUT DROP
# aus einer zweiten Sitzung prüfen, dann Rollback-Job beenden und Regeln speichern
```

### Host-Härtung (Lynis 77 → 82)

- sysctl: `kptr_restrict`, `sysrq`, `unprivileged_bpf_disabled`, `bpf_jit_harden`, `suid_dumpable`, `protected_fifos`, Protokollierung von Martian-Paketen, ICMP-Redirects. `ip_forward` und `rp_filter` bleiben wegen des Container-Netzwerks unverändert.
- Ungenutzte Protokolle (`dccp`, `sctp`, `rds`, `tipc`) und `usb-storage` gesperrt
- Core Dumps deaktiviert, sysstat und debsums-Cron aktiviert, alte `rc`-Pakete bereinigt
- AIDE: Die Distributionskonfiguration erzeugte eine leere Datenbank (`Number of entries: 0`). Deshalb wurde eine eigenständige Konfiguration für `/boot /etc /usr /root/.ssh` hinzugefügt, mit täglicher Prüfung und E-Mail bei Änderungen.

Bewusst ausgelassen auf einem Produktivsystem: separate Partitionen, GRUB-Passwort, globales `umask 027`, `hidepid` und globales `allow_url_fopen=Off`.

## Vorfälle während der Arbeit (und was sie gelehrt haben)

| Vorfall | Ursache | Lösung | Erkenntnis |
| --- | --- | --- | --- |
| Apache down (`Address already in use :80`) | Certbot hing im Standalone-Modus auf Port 80 während eines Timer-Laufs, nachdem `pre_hook` Apache gestoppt hatte | Certbot beendet, Umstellung auf gemeinsamen Webroot | Ein Erneuerungsjob darf nie den Lebenszyklus des Webservers steuern |
| MariaDB startete nach einer Konfigurationsänderung nicht | `/tmp` hatte den Modus `1777` verloren, InnoDB konnte keine temporären Dateien anlegen | `chmod 1777 /tmp` | Ein Neustart deckt verborgene Fehler auf. Erst das Basis-Dateisystem prüfen, dann die Änderung verdächtigen |
| Load Average ~1 → 4–6, Dienste fielen aus | Ein SpamAssassin-Trainingsskript kopierte ~187.000 Mails (52 GB) in ein temporäres Verzeichnis. Sein `-ctime`-Filter traf weit mehr als beabsichtigt, es räumte bei Fehlern nicht auf und füllte `/`. Danach lief rsyslog in einem Container mit ~35.000 Zeilen/Minute in eine Fehlerschleife | Temporäre Daten gelöscht, Skript neu geschrieben, Container-journald begrenzt | Speicherintensive Jobs brauchen eine Prüfung des freien Platzes, Aufräumen per `trap`, `-mtime` statt `-ctime` und ein Zielvolume, das nicht `/` ist |
| Hohe MariaDB-CPU-Last durch einen Onlineshop | Nicht indizierte `WHERE`-Abfrage auf einer Produkttabelle mit 117.000 Zeilen, mehrmals pro Sekunde | `ALTER TABLE ... ADD INDEX` | Vor dem Tuning des Servers `SHOW PROCESSLIST` prüfen |

### Neu geschriebenes Trainingsskript (Kern)

```bash
LIST=$(mktemp "$BASE/list.XXXXXX"); T=$(mktemp -d "$BASE/satrain.XXXXXX")
trap 'rm -rf -- "$T" "$LIST"' EXIT INT TERM
# ... NUL-getrennte Liste mit -mtime -N -size -512k erstellen, Anzahl pro Ordner ausgeben ...
[ $((MB + 2048)) -gt "$FREE" ] && { echo "nicht genug Platz"; exit 1; }
pv -0 -l -s "$N" < "$LIST" | xargs -0 -r cp --backup=numbered -t "$T"
chown -R amavis "$T"
nice -n 19 ionice -c3 sudo -u amavis -H sa-learn --"$MODE" --progress "$T"
```

Ergebnis: Das Spam/Ham-Verhältnis der Bayes-Datenbank sank von 20:1 (23.933 / 1.169) auf 1,8:1 (23.933 / 13.363), nachdem ~12.000 legitime gesendete Nachrichten aus 300 Tagen gelernt wurden.

## Ergebnisse

- Aus dem Internet erreichbare interne Dienste: **5 → 0** (MariaDB, NRPE, rpcbind, doppelter VNC, unbeschränktes SFTP)
- Admin-Ports der Container auf eine einzige Admin-IP beschränkt
- Lynis-Härtungsindex **77 → 82**, 0 Warnungen
- Zertifikatserneuerung verursacht keinen Ausfall des Webservers mehr
- Vorfall mit vollem Dateisystem vollständig nachverfolgt und gegen Wiederholung abgesichert

## Offene Empfehlungen

1. Firewall auf Default-Deny umstellen (Verfahren oben).
2. Ältere PHP-Versionen absichern: `disable_functions`, `open_basedir` und `allow_url_fopen` pro Pool.
3. ModSecurity nach Prüfung der Fehlalarme von `DetectionOnly` auf `On` umstellen.
4. Dovecot: `disable_plaintext_auth = yes`, `ssl = required`.
5. Default-vhost auf der reinen IP liefert 403 statt der Distributionsseite.
6. Monitoring-Alarme für Speicherplatz und Zertifikatsablauf, da die Erneuerung jetzt manuell erfolgt.

## Werkzeuge

`nmap`, `ss`, `Test-NetConnection`, `Resolve-DnsName`, Lynis, AIDE, fail2ban, iptables/ip6tables, Incus, certbot, MariaDB `PROCESSLIST`, `htop`, `journalctl`, `pv`, `sa-learn`.
