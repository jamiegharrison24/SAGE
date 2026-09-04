# attack_mapper vs. hand-audited sample

- matched audit rows: **100**
- scoreable (non-ambiguous) rows: **80**
- top-1 correct vs. hand-audit proposed technique: **43/80 = 53.8%**
- flagged for human review: 89/100 (89.0%)
- source breakdown (top-1 mapping's source): {'bridge_table': 69, 'tier2_combined': 6, 'embedding': 12, 'declared': 11, 'ioc_alias': 2}
- wall time: 10.0s for 100 rows

**Baseline for comparison** (`archive/tiered_approach/tier2_vs_audit_findings.md`, TF-IDF classifier trained on 26,644-row ET-labeled corpus): 27/79 = 34.2% top-1.

**Coverage caveat**: the brief asks for a 200+-rule labeled regression set; this harness only has 100 hand-audited rows (80 scoreable) to draw on. Treat the number above as directional, not a satisfied validation bar.

## Miss / skip rows

| proposed | mapper top-1 (source, conf) | verdict | signature |
|---|---|---|---|
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible Qmail CVE-2014-6271 Mail From attempt |
| TA0011 | T1486 (tier2_combined, 0.31) | SKIPPED | ET CNC Ransomware Tracker Reported CnC Server group 101 |
| (none) - maybe weak T1071.003 | T1667 (embedding, 0.15) | SKIPPED | SURICATA SMTP invalid pipelined sequence |
| T1595 | T1018 (bridge_table, 0.70) | MISS | ET SCAN NETWORK Incoming Masscan detected |
| T1595 | T1018 (bridge_table, 0.70) | MISS | ET SCAN External to Internal UPnP Request udp port 1900 |
| (none) - non-malicious | T1105 (bridge_table, 0.40) | SKIPPED | ET P2P Edonkey Publicize File ACK |
| (none) | T1190 (embedding, 0.14) | SKIPPED | SURICATA HTTP response field missing colon |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible CVE-2014-6271 exploit attempt via malicious DNS |
| T1190 | T1203 (bridge_table, 0.40) | MISS | GPL WEB_SERVER perl post attempt |
| (none) | T1071.003 (embedding, 0.15) | SKIPPED | SURICATA SMTP data command rejected |
| (none) | T1213.005 (embedding, 0.19) | SKIPPED | GPL CHAT Jabber/Google Talk Outgoing Traffic |
| T1595.002 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER Tilde in URI - potential .inc source disclosure vulnerability |
| T1189 | T1104 (embedding, 0.14) | MISS | ET CURRENT_EVENTS Nuclear EK Landing Apr 08 2015 |
| ambiguous: T1595.002 / T1190 / T1212 | T1595.002 (bridge_table, 0.70) | SKIPPED | ET CURRENT_EVENTS Malformed HeartBeat Response |
| T1190 | T1071.003 (embedding, 0.19) | MISS | ET EXPLOIT Exim/Dovecot Possible MAIL FROM Command Execution |
| T1190 | T1105 (bridge_table, 0.40) | MISS | ET WEB_SPECIFIC_APPS p-Table for WordPress wptable-tinymce.php ABSPATH Parameter RFI Attempt |
| T1190 | T1041 (bridge_table, 0.40) | MISS | GPL EXPLOIT ISAPI .idq attempt |
| T1498 | T1499 (bridge_table, 0.70) | MISS | ET CURRENT_EVENTS Likely Linux/Xorddos DDoS Attack Participation (gggatat456.com) |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET POLICY Suspicious inbound to mySQL port 3306 |
| T1190 | T1203 (bridge_table, 0.40) | MISS | SERVER-MYSQL yaSSL SSL Hello Message buffer overflow attempt |
| T1068 | T1003.007 (embedding, 0.18) | MISS | OS-LINUX Linux Kernel keyring object exploit download attempt |
| ambiguous: T1210 | T1203 (bridge_table, 0.40) | SKIPPED | GPL MISC UPnP malformed advertisement |
| T1046 | T1592 (bridge_table, 0.40) | MISS | ET SCAN MySQL Malicious Scanning 1 |
| T1595 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) |
| (none) | T1016 (embedding, 0.20) | SKIPPED | ET POLICY Cisco Device New Config Built |
| T1210 | T1190 (tier2_combined, 0.29) | MISS | ET EXPLOIT Cisco Smart Install Exploitation Tool - ChangeConfig |
| T1190 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP SESSION SuperGlobal in URI |
| (none) | T1027.015 (embedding, 0.17) | SKIPPED | SURICATA HTTP gzip decompression failed |
| T1190 | T1082 (declared, 1.00) | MISS | ET EXPLOIT FortiOS SSL VPN - Information Disclosure (CVE-2018-13379) |
| T1046 | T1592 (bridge_table, 0.40) | MISS | GPL RPC xdmcp info query |
| (none) | T1190 (embedding, 0.13) | SKIPPED | SURICATA TLS invalid record type |
| ambiguous: T1110 / T1078.001 | T1110 (bridge_table, 0.70) | SKIPPED | GPL POLICY Sun JavaServer default password login attempt |
| T1190 | T1592 (bridge_table, 0.40) | MISS | GPL FTP CWD .... attempt |
| T1595 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Httprecon Web Server Fingerprint Scan |
| T1190 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP ENV SuperGlobal in URI |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible CVE-2013-0156 Ruby On Rails XML YAML tag with !ruby |
| (none) - likely non-malicious/policy | T1003.007 (embedding, 0.15) | SKIPPED | ET POLICY Http Client Body contains pwd= in cleartext |
| ambiguous | T1592 (bridge_table, 0.40) | SKIPPED | GPL ATTACK_RESPONSE directory listing |
| ambiguous - weak/non-malicious leaning | T1592 (bridge_table, 0.40) | SKIPPED | ET USER_AGENTS Go HTTP Client User-Agent |
| (none) | T1588.004 (embedding, 0.14) | SKIPPED | SURICATA TLS certificate invalid length |
| ambiguous | T1203 (bridge_table, 0.40) | SKIPPED | ETPRO EXPLOIT Possible HTML Meta Refresh (CVE-2015-6123) Inbound to Server |
| ambiguous: TA0011 / T1059 | T1049 (ioc_alias, 0.75) | SKIPPED | ET TROJAN Windows netstat Microsoft Windows DOS prompt command exit OUTBOUND |
| T1021.001 | T1068 (bridge_table, 0.40) | MISS | ET POLICY MS Remote Desktop Administrator Login Request |
| T1059.003 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER cmd.exe In URI - Possible Command Execution Attempt |
| ambiguous - no clean technique | T1041 (bridge_table, 0.40) | SKIPPED | OS-OTHER Intel x86 side-channel analysis information leak attempt |
| T1210 | T1203 (bridge_table, 0.40) | MISS | GPL NETBIOS SMB-DS Session Setup NTMLSSP asn1 overflow attempt |
| T1498 | T1499 (bridge_table, 0.70) | MISS | ET DOS MC-SQLR Response Outbound Possible DDoS Participation |
| T1098.004 | T1041 (bridge_table, 0.40) | MISS | ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration |
| T1190 | T1083 (declared, 1.00) | MISS | ET WEB_SPECIFIC_APPS Oracle JSF2 Path Traversal Attempt |
| T1190 | T1041 (bridge_table, 0.40) | MISS | GPL EXPLOIT /iisadmpwd/aexp2.htr access |
| T1190 | T1592 (bridge_table, 0.40) | MISS | GPL FTP CWD ~root attempt |
| (none) - non-malicious | T1105 (bridge_table, 0.40) | SKIPPED | ET P2P BitTorrent DHT announce_peers request |
| T1595 | T1018 (bridge_table, 0.70) | MISS | ET SCAN NMAP -sA (1) |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | GPL WEB_SERVER writeto.cnf access |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | GPL WEB_SERVER service.pwd |
| T1021.002 | T1041 (bridge_table, 0.40) | MISS | GPL NETBIOS SMB-DS ADMIN$ share access |
| T1018 | T1016 (ioc_alias, 0.75) | MISS | ET SCAN NBTStat Query Response to External Destination Possible Windows Network Enumeration |

## Hit rows

| proposed | mapper top-1 (source, conf) | signature |
|---|---|---|
| T1046 | T1046 (bridge_table, 0.70) | GPL RPC portmap listing UDP 111 |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Potential VNC Scan 5800-5820 |
| T1203 | T1203 (bridge_table, 0.40) | ETPRO EXPLOIT Possible EDGE OOB Access (CVE-2016-0193) |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS SolarWinds TFTP Server Long Write Request Denial Of Service Attempt |
| T1018 | T1018 (bridge_table, 0.70) | ET SCAN DCERPC rpcmgmt ifids Unauthenticated BIND |
| T1592;T1590 | T1592 (bridge_table, 0.40) | ET SCAN Internet Scanning Project HTTP scan |
| T1496 | T1496 (bridge_table, 0.70) | ETPRO TROJAN CoinMiner Known Malicious Stratum Authline |
| T1018 | T1018 (bridge_table, 0.70) | GPL SCAN ISS Pinger |
| T1190 | T1190 (declared, 1.00) | ET WEB_SERVER SQL Injection Local File Access Attempt Using LOAD_FILE |
| T1190 | T1190 (declared, 1.00) | ET WEB_SERVER SELECT USER SQL Injection Attempt in URI |
| T1190 | T1190 (declared, 1.00) | ET WEB_SERVER PHP Possible php Remote File Inclusion Attempt |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection |
| T1105 | T1105 (bridge_table, 0.40) | ET POLICY SMB2 NT Create AndX Request For a .bat File |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN OpenVAS User-Agent Inbound |
| T1190 | T1190 (tier2_combined, 0.33) | ETPRO EXPLOIT Possible Jetty Web Server Information Leak Attempt |
| T1499 | T1499 (bridge_table, 0.70) | SERVER-APACHE Apache APR header memory corruption attempt |
| T1018 | T1018 (bridge_table, 0.70) | ETPRO SCAN Internal Machine Scanning VNC - Outbound Traffic |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS phPortal gunaysoft.php sayfaid Parameter Remote File Inclusion |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS BASE base_stat_common.php remote file include |
| T1203 | T1203 (bridge_table, 0.40) | OS-WINDOWS Microsoft Windows DNS client TXT buffer overrun attempt |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN GET with HTML tag in start of URI seen with PHPMyAdmin scanning |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS PithCMS oldnews_reader.php lang Parameter Local File Inclusion Attempt |
| T1595.002 | T1595.002 (bridge_table, 0.70) | INDICATOR-SCAN PHP backdoor scan attempt |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS SMBLoris NBSS Length Mem Exhaustion Attempt (PoC Based) |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS DNS BIND 9 Dynamic Update DoS attempt |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Possible Microsoft SQL Server Remote Denial Of Service Attempt |
| T1203 | T1203 (bridge_table, 0.40) | FILE-IMAGE Adobe Acrobat TIFF Software tag heap buffer overflow attempt |
| T1203 | T1203 (bridge_table, 0.40) | ET EXPLOIT Possible IE Scripting Engine Memory Corruption Vulnerability (CVE-2019-0752) |
| T1190 | T1190 (declared, 1.00) | ET WEB_SERVER PHP Possible https Local File Inclusion Attempt |
| T1190 | T1190 (tier2_combined, 0.39) | ETPRO EXPLOIT Possible HP.SSF.WebService Exploit Attempt |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Medusa User-Agent |
| T1105 | T1105 (bridge_table, 0.40) | ET CURRENT_EVENTS Terse alphanumeric executable downloader high likelihood of being hostile |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS Joomla 3.7.0 - Sql Injection (CVE-2017-8917) |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Possible MYSQL GeomFromWKB() function Denial Of Service Attempt |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN PHP Attack Tool Morfeus F Scanner |
| T1190 | T1190 (tier2_combined, 0.42) | ET EXPLOIT LastPass RCE Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS KR-Web krgourl.php DOCUMENT_ROOT Parameter Remote File Inclusion Attempt |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Microsoft Streaming Server Malformed Request |
| T1046 | T1046 (bridge_table, 0.70) | GPL POLICY PCAnywhere server response |
| T1190 | T1190 (tier2_combined, 0.38) | ET WEB_SERVER open_basedir PHP config option in uri |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Excessive SMTP MAIL-FROM DDoS |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Cisco Router HTTP DoS |
