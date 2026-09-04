# Tier 2 (ET+Sigma combined corpus) vs. hand-audited sample

- matched audit rows found in tier2_combined_predictions.csv: **99**
- scoreable (non-ambiguous) rows: **79**
- top-1 correct vs. hand-audit proposed technique: **30/79 = 38.0%**
- combined predicted T1190 as top-1 in **52/99 = 52.5%** of all matched rows

**Baseline for comparison** (`tier2_vs_audit_findings.md`, ET-only corpus): 27/79 = 34.2% top-1, T1190 top-1 in 76.8% of rows.

## Miss rows

| proposed | current_gt | combined_pred (score) | signature |
|---|---|---|---|
| T1046 | T1046 | T1041 (-0.4049) | GPL RPC portmap listing UDP 111 |
| T1046 | T1046 | T1190 (0.0887) | ET SCAN Potential VNC Scan 5800-5820 |
| T1595 | T1018 | T1059 (-0.0059) | ET SCAN NETWORK Incoming Masscan detected |
| T1595 | T1018 | T1614 (-0.2945) | ET SCAN External to Internal UPnP Request udp port 1900 |
| T1203 | T1203 | T1190 (1.0121) | ETPRO EXPLOIT Possible EDGE OOB Access (CVE-2016-0193) |
| T1499 | T1499 | T1190 (0.7143) | ET DOS SolarWinds TFTP Server Long Write Request Denial Of Service Attempt |
| T1595.002 | T1041 | T1082 (0.0856) | ET WEB_SERVER Tilde in URI - potential .inc source disclosure vulnerability |
| T1189 | TA0011 | T1566 (-0.6099) | ET CURRENT_EVENTS Nuclear EK Landing Apr 08 2015 |
| T1018 | T1018 | T1190 (0.0540) | ET SCAN DCERPC rpcmgmt ifids Unauthenticated BIND |
| T1592;T1590 | T1592;T1590 | T1046 (0.5836) | ET SCAN Internet Scanning Project HTTP scan |
| T1498 | T1499 | T1033 (-0.5469) | ET CURRENT_EVENTS Likely Linux/Xorddos DDoS Attack Participation (gggatat456.com) |
| T1046 | T1595.002 | T1547.010 (-0.5932) | ET POLICY Suspicious inbound to mySQL port 3306 |
| T1018 | T1018 | T1190 (0.2191) | GPL SCAN ISS Pinger |
| T1068 | TA0004 | T1083 (-0.5161) | OS-LINUX Linux Kernel keyring object exploit download attempt |
| T1046 | T1046 | T1059 (-0.1504) | ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection |
| T1105 | T1105 | T1570 (-0.0925) | ET POLICY SMB2 NT Create AndX Request For a .bat File |
| T1595 | T1018 | T1046 (0.1439) | ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) |
| T1210 | (none) | T1190 (0.2978) | ET EXPLOIT Cisco Smart Install Exploitation Tool - ChangeConfig |
| T1595.002 | T1595.002 | T1190 (0.1302) | ET SCAN OpenVAS User-Agent Inbound |
| T1499 | T1499 | T1190 (-0.3398) | SERVER-APACHE Apache APR header memory corruption attempt |
| T1018 | T1018 | T1046 (-0.1634) | ETPRO SCAN Internal Machine Scanning VNC - Outbound Traffic |
| T1190 | T1592;T1590 | T1082 (0.9964) | ET EXPLOIT FortiOS SSL VPN - Information Disclosure (CVE-2018-13379) |
| T1046 | T1592;T1590 | T1568 (-0.2728) | GPL RPC xdmcp info query |
| T1595 | T1018 | T1190 (0.8550) | ET SCAN Httprecon Web Server Fingerprint Scan |
| T1203 | T1203 | T1189 (-0.1970) | OS-WINDOWS Microsoft Windows DNS client TXT buffer overrun attempt |
| T1595.002 | T1595.002 | T1046 (0.0173) | ET SCAN GET with HTML tag in start of URI seen with PHPMyAdmin scanning |
| T1595.002 | T1595.002 | T1190 (1.0274) | INDICATOR-SCAN PHP backdoor scan attempt |
| T1499 | T1499 | T1190 (0.2765) | ET DOS SMBLoris NBSS Length Mem Exhaustion Attempt (PoC Based) |
| T1021.001 | T1068 | T1078 (-0.0780) | ET POLICY MS Remote Desktop Administrator Login Request |
| T1059.003 | T1203 | T1190 (0.0661) | ET WEB_SERVER cmd.exe In URI - Possible Command Execution Attempt |
| T1498 | T1498 | T1565.001 (0.3167) | ET DOS DNS BIND 9 Dynamic Update DoS attempt |
| T1499 | T1499 | T1190 (1.0089) | ET DOS Possible Microsoft SQL Server Remote Denial Of Service Attempt |
| T1203 | T1203 | T1190 (-0.1865) | FILE-IMAGE Adobe Acrobat TIFF Software tag heap buffer overflow attempt |
| T1203 | T1203 | T1190 (0.3407) | ET EXPLOIT Possible IE Scripting Engine Memory Corruption Vulnerability (CVE-2019-0752) |
| T1210 | T1203 | T1190 (0.1493) | GPL NETBIOS SMB-DS Session Setup NTMLSSP asn1 overflow attempt |
| T1498 | T1499 | T1495 (0.0414) | ET DOS MC-SQLR Response Outbound Possible DDoS Participation |
| T1110 | T1110 | T1071.001 (0.2155) | ET SCAN Medusa User-Agent |
| T1098.004 | T1041 | T1190 (0.5626) | ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration |
| T1190 | T1592;T1590 | T1083 (0.9960) | ET WEB_SPECIFIC_APPS Oracle JSF2 Path Traversal Attempt |
| T1499 | T1499 | T1565.001 (0.4972) | ET DOS Possible MYSQL GeomFromWKB() function Denial Of Service Attempt |
| T1595.002 | T1595.002 | T1046 (0.2008) | ET SCAN PHP Attack Tool Morfeus F Scanner |
| T1498 | T1498 | T1190 (0.1075) | ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt |
| T1595 | T1018 | T1046 (1.3697) | ET SCAN NMAP -sA (1) |
| T1595.002 | T1592;T1590 | T1190 (0.4481) | GPL WEB_SERVER writeto.cnf access |
| T1595.002 | T1592;T1590 | T1190 (0.2981) | GPL WEB_SERVER service.pwd |
| T1498 | T1498 | T1190 (0.2701) | ET DOS Microsoft Streaming Server Malformed Request |
| T1046 | T1046 | T1082 (-0.5275) | GPL POLICY PCAnywhere server response |
| T1499 | T1499 | T1495 (0.2413) | ET DOS Excessive SMTP MAIL-FROM DDoS |
| T1498 | T1498 | T1495 (0.6058) | ET DOS Cisco Router HTTP DoS |

## Hit rows

| proposed | combined_pred (score) | signature |
|---|---|---|
| T1190 | T1190 (0.9994) | ET EXPLOIT Possible Qmail CVE-2014-6271 Mail From attempt |
| T1190 | T1190 (0.7826) | ET EXPLOIT Possible CVE-2014-6271 exploit attempt via malicious DNS |
| T1190 | T1190 (0.5096) | GPL WEB_SERVER perl post attempt |
| T1190 | T1190 (-0.4096) | ET EXPLOIT Exim/Dovecot Possible MAIL FROM Command Execution |
| T1190 | T1190 (1.8602) | ET WEB_SPECIFIC_APPS p-Table for WordPress wptable-tinymce.php ABSPATH Parameter RFI Attempt |
| T1190 | T1190 (1.6418) | GPL EXPLOIT ISAPI .idq attempt |
| T1496 | T1496 (0.0594) | ETPRO TROJAN CoinMiner Known Malicious Stratum Authline |
| T1190 | T1190 (0.0062) | SERVER-MYSQL yaSSL SSL Hello Message buffer overflow attempt |
| T1190 | T1190 (0.8129) | ET WEB_SERVER SQL Injection Local File Access Attempt Using LOAD_FILE |
| T1190 | T1190 (1.7800) | ET WEB_SERVER SELECT USER SQL Injection Attempt in URI |
| T1190 | T1190 (1.5046) | ET WEB_SERVER PHP Possible php Remote File Inclusion Attempt |
| T1046 | T1046 (0.2577) | ET SCAN MySQL Malicious Scanning 1 |
| T1190 | T1190 (0.5190) | ET WEB_SERVER PHP SESSION SuperGlobal in URI |
| T1190 | T1190 (0.6293) | ETPRO EXPLOIT Possible Jetty Web Server Information Leak Attempt |
| T1190 | T1190 (1.5492) | ET WEB_SPECIFIC_APPS phPortal gunaysoft.php sayfaid Parameter Remote File Inclusion |
| T1190 | T1190 (1.5774) | ET WEB_SPECIFIC_APPS BASE base_stat_common.php remote file include |
| T1190 | T1190 (-0.0697) | GPL FTP CWD .... attempt |
| T1190 | T1190 (0.4961) | ET WEB_SERVER PHP ENV SuperGlobal in URI |
| T1190 | T1190 (0.5390) | ET WEB_SERVER Possible CVE-2013-0156 Ruby On Rails XML YAML tag with !ruby |
| T1190 | T1190 (2.0896) | ET WEB_SPECIFIC_APPS PithCMS oldnews_reader.php lang Parameter Local File Inclusion Attempt |
| T1190 | T1190 (1.4591) | ET WEB_SERVER PHP Possible https Local File Inclusion Attempt |
| T1190 | T1190 (1.2902) | ETPRO EXPLOIT Possible HP.SSF.WebService Exploit Attempt |
| T1105 | T1105 (-0.4032) | ET CURRENT_EVENTS Terse alphanumeric executable downloader high likelihood of being hostile |
| T1190 | T1190 (2.5087) | ET WEB_SPECIFIC_APPS Joomla 3.7.0 - Sql Injection (CVE-2017-8917) |
| T1190 | T1190 (1.6903) | ET EXPLOIT LastPass RCE Attempt |
| T1190 | T1190 (0.2085) | GPL EXPLOIT /iisadmpwd/aexp2.htr access |
| T1190 | T1190 (2.3228) | ET WEB_SPECIFIC_APPS KR-Web krgourl.php DOCUMENT_ROOT Parameter Remote File Inclusion Attempt |
| T1190 | T1190 (0.0485) | GPL FTP CWD ~root attempt |
| T1021.002 | T1021.002 (0.6905) | GPL NETBIOS SMB-DS ADMIN$ share access |
| T1190 | T1190 (1.1325) | ET WEB_SERVER open_basedir PHP config option in uri |
