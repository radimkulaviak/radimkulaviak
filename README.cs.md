[English](README.md) | [Deutsch](README.de.md) | **Čeština**

# Bezpečnostní audit a hardening produkčního serveru se sdíleným hostingem

Případová studie: audit a hardening běžícího multi-tenant LAMP a mailového serveru, včetně výpadků, které při tom vznikly, a jejich řešení. Všechny identifikující údaje jsou anonymizované: IP adresy jsou z dokumentačních rozsahů podle RFC 5737, názvy hostů, domény klientů a porty jsou zobecněné.

## Prostředí

| Položka | Hodnota |
| --- | --- |
| OS | Ubuntu 24.04 LTS, jádro 6.8 |
| Provoz | Sdílený hosting, 350+ webů klientů, 280+ databází MariaDB, autoritativní DNS pro 240+ domén |
| Stack | Apache 2.4 + ModSecurity, PHP-FPM (více verzí, pool pro každý web), MariaDB 10.11, Postfix, Dovecot, Amavis/SpamAssassin/ClamAV, BIND 9, ProFTPD, fail2ban |
| Navíc | Kontejnery Incus (jedna grafická aplikace za VNC), Nagios + NRPE |
| Omezení | Produkční stroj bez servisního okna, staré verze PHP, které nejde odstranit |

## Postup

1. **Pohled zvenku.** Sken portů všech veřejných IP mimo vlastní síť (`nmap`, PowerShell `Test-NetConnection` z domácí přípojky) a kontrola DNS: otevřená rekurze a AXFR.
2. **Pohled zevnitř.** `ss -tulpn` ukazuje, co skutečně poslouchá na veřejných rozhraních. Výsledek se porovnal se skenem.
3. **Audit hostitele.** Výchozí stav podle Lynis 3.1.7: hardening index **77**, 0 varování, 39 doporučení.
4. **Opravy po malých, vratných krocích**, každý krok ověřený zvenku.

Hned na začátku se ukázalo: `nmap` spuštěný ze serveru na jeho vlastní hostname se přes `/etc/hosts` přeložil na `127.0.0.1`. Ukázal tak i služby dostupné jen lokálně (Amavis, porty pro reinjekci v Postfixu), takže nešlo o platný pohled zvenku.

## Nálezy

| # | Nález | Riziko | Stav |
| --- | --- | --- | --- |
| 1 | Politika iptables `INPUT` je `ACCEPT`: každá nová služba na `0.0.0.0` byla hned veřejná | Vysoké | Příčina nalezena, default-deny naplánováno |
| 2 | MariaDB 3306 dostupná z internetu | Vysoké | Opraveno: vázáno na `127.0.0.1` |
| 3 | VNC (2 porty) a SFTP do kontejneru vystavené přes incus proxy na `0.0.0.0`, povolovací pravidlo pro IP mělo jen jeden port | Vysoké | Opraveno: duplicitní proxy odstraněna, zbylé porty omezené na IP správce |
| 4 | NRPE 5666 veřejně (monitorovací server je lokální) | Střední | Opraveno: `server_address=127.0.0.1` |
| 5 | rpcbind 111 veřejně, NFS se nepoužívá | Střední | Opraveno: služba vypnutá |
| 6 | xrdp nainstalovaný a zapnutý, nepoužívaný | Střední | Opraveno: odinstalováno |
| 7 | Obnova certifikátů certbotem používala `pre_hook = systemctl stop apache2` u 113 certifikátů | Dostupnost | Opraveno: společný webroot, žádné zastavování Apache |
| 8 | Zastaralý záznam v `/etc/hosts` s už nepoužívanou IP | Nízké | Opraveno |
| 9 | Jádro/sysctl, nepoužívané protokoly, core dumpy, process accounting apod. (Lynis) | Nízké | Částečně opraveno (index 77 → 82) |
| 10 | Otevřený DNS resolver | — | Není zranitelný: rekurze zvenku `REFUSED`, AXFR odmítnut |

## Hlavní opravy

### Incus proxy jen na localhost / IP správce

```bash
incus config device remove <ct> vnc-dup
incus config device set <ct> sftp-port listen tcp:127.0.0.1:2223
# přístup správce přes SSH tunel, nebo explicitní povolovací pravidlo:
iptables -I INPUT 1 -s 198.51.100.7/32 -p tcp --dport 5901 -j ACCEPT
iptables -I INPUT 2 -p tcp --dport 5901 -j DROP
```

### MariaDB jen lokálně

```bash
ss -tn state established '( sport = :3306 )'      # nejdřív ověřit, že se nikdo nepřipojuje zvenku
sed -i 's/^\s*bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mariadb.conf.d/50-server.cnf
systemctl restart mariadb
```

### Certbot bez výpadku

Certbot používal režim `standalone` nebo hooky stop/start, takže se Apache při každé obnově vypnul. Když se obnova zasekla, weby zůstaly mimo provoz. Řešením je jeden společný ACME webroot pro všechny vhosty, bez hooků:

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

Paralelní kontrola přes `curl` na všechny SAN všech certifikátů našla certifikáty pro domény hostované jinde nebo mířící na už nepoužívanou IP. Jsou určené ke smazání.

### Firewall default-deny s automatickým rollbackem (naplánováno)

```bash
iptables-save > /root/iptables.bak; ip6tables-save > /root/ip6tables.bak
nohup sh -c 'sleep 300; iptables-restore < /root/iptables.bak; ip6tables-restore < /root/ip6tables.bak' &
# povolit lo, ESTABLISHED/RELATED, bridge kontejnerů a porty hostingu, pak:
iptables -P INPUT DROP; ip6tables -P INPUT DROP
# ověřit z druhé session, pak zrušit rollback a pravidla uložit
```

### Hardening hostitele (Lynis 77 → 82)

- sysctl: `kptr_restrict`, `sysrq`, `unprivileged_bpf_disabled`, `bpf_jit_harden`, `suid_dumpable`, `protected_fifos`, logování martian paketů, ICMP redirecty. `ip_forward` a `rp_filter` zůstaly beze změny kvůli síti kontejnerů.
- Zakázané nepoužívané protokoly (`dccp`, `sctp`, `rds`, `tipc`) a `usb-storage`
- Vypnuté core dumpy, zapnutý sysstat a cron pro debsums, vyčištěné staré balíčky ve stavu `rc`
- AIDE: distribuční konfigurace vytvářela prázdnou databázi (`Number of entries: 0`). Přidala se proto samostatná konfigurace pro `/boot /etc /usr /root/.ssh` s denní kontrolou a mailem při změně.

Na produkčním stroji záměrně vynecháno: oddělené partition, heslo na GRUB, globální `umask 027`, `hidepid` a globální `allow_url_fopen=Off`.

## Incidenty během práce (a co z nich plyne)

| Incident | Příčina | Oprava | Ponaučení |
| --- | --- | --- | --- |
| Apache neběžel (`Address already in use :80`) | Certbot v režimu standalone se zasekl na portu 80 během běhu timeru poté, co `pre_hook` zastavil Apache | Ukončení certbotu, přechod na společný webroot | Obnova certifikátů nesmí řídit start a stop webserveru |
| MariaDB po změně konfigurace nenaběhla | `/tmp` ztratil práva `1777`, InnoDB nemohl vytvořit dočasné soubory | `chmod 1777 /tmp` | Restart odhalí skrytou chybu. Nejdřív zkontrolovat základní souborový systém, až pak podezírat změnu |
| Load average ~1 → 4–6, padající služby | Skript pro učení SpamAssassinu zkopíroval ~187 tisíc mailů (52 GB) do dočasného adresáře. Filtr `-ctime` zachytil mnohem víc, než měl, skript po chybě neuklidil a zaplnil `/`. rsyslog v kontejneru se pak zacyklil na chybách zápisu, ~35 tisíc řádků za minutu | Smazání dočasných dat, přepsaný skript, omezený journald v kontejneru | Úlohy náročné na místo potřebují kontrolu volného místa, úklid přes `trap`, `-mtime` místo `-ctime` a cílový svazek jiný než `/` |
| Vysoké vytížení CPU v MariaDB kvůli jednomu e-shopu | Neindexovaný `WHERE` na tabulce produktů se 117 tisíci řádky, několikrát za sekundu | `ALTER TABLE ... ADD INDEX` | Před laděním serveru se podívat do `SHOW PROCESSLIST` |

### Přepsaný skript pro učení (jádro)

```bash
LIST=$(mktemp "$BASE/list.XXXXXX"); T=$(mktemp -d "$BASE/satrain.XXXXXX")
trap 'rm -rf -- "$T" "$LIST"' EXIT INT TERM
# ... seznam oddělený NUL s -mtime -N -size -512k, výpis počtů po složkách ...
[ $((MB + 2048)) -gt "$FREE" ] && { echo "malo mista"; exit 1; }
pv -0 -l -s "$N" < "$LIST" | xargs -0 -r cp --backup=numbered -t "$T"
chown -R amavis "$T"
nice -n 19 ionice -c3 sudo -u amavis -H sa-learn --"$MODE" --progress "$T"
```

Výsledek: poměr spam/ham v Bayes databázi klesl z 20:1 (23 933 / 1 169) na 1,8:1 (23 933 / 13 363) po naučení ~12 tisíc legitimních odeslaných zpráv za 300 dní.

## Výsledky

- Interní služby dostupné z internetu: **5 → 0** (MariaDB, NRPE, rpcbind, duplicitní VNC, neomezené SFTP)
- Správcovské porty kontejnerů omezené na jedinou IP správce
- Hardening index Lynis **77 → 82**, 0 varování
- Obnova certifikátů už nezpůsobuje výpadek webu
- Incident s plným diskem dohledaný od příčiny po následky a ošetřený proti opakování

## Otevřená doporučení

1. Přepnout firewall na default-deny (postup výše).
2. Zabezpečit staré verze PHP: `disable_functions`, `open_basedir` a `allow_url_fopen` po jednotlivých poolech.
3. Po kontrole falešných poplachů přepnout ModSecurity z `DetectionOnly` na `On`.
4. Dovecot: `disable_plaintext_auth = yes`, `ssl = required`.
5. Výchozí vhost na samotné IP vrací 403, ne stránku distribuce.
6. Monitoring zaplnění disku a expirace certifikátů, protože obnova je teď ruční.

## Nástroje

`nmap`, `ss`, `Test-NetConnection`, `Resolve-DnsName`, Lynis, AIDE, fail2ban, iptables/ip6tables, Incus, certbot, MariaDB `PROCESSLIST`, `htop`, `journalctl`, `pv`, `sa-learn`.
