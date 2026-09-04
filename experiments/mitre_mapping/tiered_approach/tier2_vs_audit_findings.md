# Tier 2 vs. hand-audited sample

- matched audit rows found in tier2_predictions.csv: **99**
- scoreable (non-ambiguous) rows: **79**
- top-1 correct vs. hand-audit proposed technique: **27/79 = 34.2%**
- tier2 predicted T1190 as top-1 in **76/99 = 76.8%** of all matched rows

## Miss rows

| proposed | current_gt | tier2_pred (score) | signature |
|---|---|---|---|
| T1046 | T1046 | T1205 (-0.5263) | GPL RPC portmap listing UDP 111 |
| T1046 | T1046 | T1190 (0.5868) | ET SCAN Potential VNC Scan 5800-5820 |
| T1595 | T1018 | T1190 (0.1491) | ET SCAN NETWORK Incoming Masscan detected |
| T1595 | T1018 | T1614 (-0.1404) | ET SCAN External to Internal UPnP Request udp port 1900 |
| T1203 | T1203 | T1190 (0.9354) | ETPRO EXPLOIT Possible EDGE OOB Access (CVE-2016-0193) |
| T1499 | T1499 | T1190 (0.8824) | ET DOS SolarWinds TFTP Server Long Write Request Denial Of Service Attempt |
| T1595.002 | T1041 | T1082 (0.0866) | ET WEB_SERVER Tilde in URI - potential .inc source disclosure vulnerability |
| T1189 | TA0011 | T1566 (-0.3763) | ET CURRENT_EVENTS Nuclear EK Landing Apr 08 2015 |
| T1018 | T1018 | T1190 (0.4044) | ET SCAN DCERPC rpcmgmt ifids Unauthenticated BIND |
| T1592;T1590 | T1592;T1590 | T1190 (0.4259) | ET SCAN Internet Scanning Project HTTP scan |
| T1498 | T1499 | T1041 (-0.3964) | ET CURRENT_EVENTS Likely Linux/Xorddos DDoS Attack Participation (gggatat456.com) |
| T1046 | T1595.002 | T1190 (-0.3917) | ET POLICY Suspicious inbound to mySQL port 3306 |
| T1018 | T1018 | T1190 (0.4033) | GPL SCAN ISS Pinger |
| T1068 | TA0004 | T1190 (-0.0807) | OS-LINUX Linux Kernel keyring object exploit download attempt |
| T1046 | T1046 | T1190 (-0.1748) | ET SCAN Behavioral Unusual Port 135 traffic Potential Scan or Infection |
| T1105 | T1105 | T1570 (-0.3877) | ET POLICY SMB2 NT Create AndX Request For a .bat File |
| T1046 | T1592;T1590 | T1190 (0.4443) | ET SCAN MySQL Malicious Scanning 1 |
| T1595 | T1018 | T1190 (0.2675) | ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) |
| T1210 | (none) | T1190 (0.4899) | ET EXPLOIT Cisco Smart Install Exploitation Tool - ChangeConfig |
| T1595.002 | T1595.002 | T1190 (0.1949) | ET SCAN OpenVAS User-Agent Inbound |
| T1499 | T1499 | T1190 (-0.1057) | SERVER-APACHE Apache APR header memory corruption attempt |
| T1018 | T1018 | T1190 (-0.3358) | ETPRO SCAN Internal Machine Scanning VNC - Outbound Traffic |
| T1190 | T1592;T1590 | T1082 (0.9980) | ET EXPLOIT FortiOS SSL VPN - Information Disclosure (CVE-2018-13379) |
| T1046 | T1592;T1590 | T1568 (-0.1961) | GPL RPC xdmcp info query |
| T1595 | T1018 | T1190 (0.5745) | ET SCAN Httprecon Web Server Fingerprint Scan |
| T1203 | T1203 | T1189 (0.4430) | OS-WINDOWS Microsoft Windows DNS client TXT buffer overrun attempt |
| T1595.002 | T1595.002 | T1190 (0.3077) | ET SCAN GET with HTML tag in start of URI seen with PHPMyAdmin scanning |
| T1595.002 | T1595.002 | T1190 (0.6962) | INDICATOR-SCAN PHP backdoor scan attempt |
| T1499 | T1499 | T1190 (0.6610) | ET DOS SMBLoris NBSS Length Mem Exhaustion Attempt (PoC Based) |
| T1021.001 | T1068 | T1190 (-0.0779) | ET POLICY MS Remote Desktop Administrator Login Request |
| T1059.003 | T1203 | T1190 (0.5348) | ET WEB_SERVER cmd.exe In URI - Possible Command Execution Attempt |
| T1498 | T1498 | T1190 (0.4629) | ET DOS DNS BIND 9 Dynamic Update DoS attempt |
| T1499 | T1499 | T1190 (1.2972) | ET DOS Possible Microsoft SQL Server Remote Denial Of Service Attempt |
| T1203 | T1203 | T1190 (0.1316) | FILE-IMAGE Adobe Acrobat TIFF Software tag heap buffer overflow attempt |
| T1203 | T1203 | T1190 (0.4666) | ET EXPLOIT Possible IE Scripting Engine Memory Corruption Vulnerability (CVE-2019-0752) |
| T1210 | T1203 | T1190 (0.4603) | GPL NETBIOS SMB-DS Session Setup NTMLSSP asn1 overflow attempt |
| T1498 | T1499 | T1190 (0.1412) | ET DOS MC-SQLR Response Outbound Possible DDoS Participation |
| T1110 | T1110 | T1190 (0.1180) | ET SCAN Medusa User-Agent |
| T1105 | T1105 | T1041 (-0.4890) | ET CURRENT_EVENTS Terse alphanumeric executable downloader high likelihood of being hostile |
| T1098.004 | T1041 | T1190 (0.0278) | ET EXPLOIT F5 BIG-IP rsync cmi authorized_keys successful exfiltration |
| T1190 | T1592;T1590 | T1083 (0.9977) | ET WEB_SPECIFIC_APPS Oracle JSF2 Path Traversal Attempt |
| T1499 | T1499 | T1190 (0.9240) | ET DOS Possible MYSQL GeomFromWKB() function Denial Of Service Attempt |
| T1595.002 | T1595.002 | T1190 (0.6686) | ET SCAN PHP Attack Tool Morfeus F Scanner |
| T1498 | T1498 | T1190 (0.7230) | ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt |
| T1595 | T1018 | T1190 (0.3330) | ET SCAN NMAP -sA (1) |
| T1595.002 | T1592;T1590 | T1190 (0.4204) | GPL WEB_SERVER writeto.cnf access |
| T1595.002 | T1592;T1590 | T1190 (0.4567) | GPL WEB_SERVER service.pwd |
| T1498 | T1498 | T1190 (0.7307) | ET DOS Microsoft Streaming Server Malformed Request |
| T1021.002 | T1041 | T1190 (0.3371) | GPL NETBIOS SMB-DS ADMIN$ share access |
| T1046 | T1046 | T1082 (-0.5642) | GPL POLICY PCAnywhere server response |
| T1499 | T1499 | T1190 (0.4884) | ET DOS Excessive SMTP MAIL-FROM DDoS |
| T1498 | T1498 | T1190 (0.5451) | ET DOS Cisco Router HTTP DoS |

## Hit rows

| proposed | tier2_pred (score) | signature |
|---|---|---|
| T1190 | T1190 (0.7519) | ET EXPLOIT Possible Qmail CVE-2014-6271 Mail From attempt |
| T1190 | T1190 (0.5078) | ET EXPLOIT Possible CVE-2014-6271 exploit attempt via malicious DNS |
| T1190 | T1190 (0.4562) | GPL WEB_SERVER perl post attempt |
| T1190 | T1190 (-0.0873) | ET EXPLOIT Exim/Dovecot Possible MAIL FROM Command Execution |
| T1190 | T1190 (1.6967) | ET WEB_SPECIFIC_APPS p-Table for WordPress wptable-tinymce.php ABSPATH Parameter RFI Attempt |
| T1190 | T1190 (1.0916) | GPL EXPLOIT ISAPI .idq attempt |
| T1496 | T1496 (0.2639) | ETPRO TROJAN CoinMiner Known Malicious Stratum Authline |
| T1190 | T1190 (0.3239) | SERVER-MYSQL yaSSL SSL Hello Message buffer overflow attempt |
| T1190 | T1190 (1.2005) | ET WEB_SERVER SQL Injection Local File Access Attempt Using LOAD_FILE |
| T1190 | T1190 (1.5566) | ET WEB_SERVER SELECT USER SQL Injection Attempt in URI |
| T1190 | T1190 (1.1745) | ET WEB_SERVER PHP Possible php Remote File Inclusion Attempt |
| T1190 | T1190 (0.5702) | ET WEB_SERVER PHP SESSION SuperGlobal in URI |
| T1190 | T1190 (0.2787) | ETPRO EXPLOIT Possible Jetty Web Server Information Leak Attempt |
| T1190 | T1190 (1.6102) | ET WEB_SPECIFIC_APPS phPortal gunaysoft.php sayfaid Parameter Remote File Inclusion |
| T1190 | T1190 (1.4346) | ET WEB_SPECIFIC_APPS BASE base_stat_common.php remote file include |
| T1190 | T1190 (-0.0897) | GPL FTP CWD .... attempt |
| T1190 | T1190 (0.4684) | ET WEB_SERVER PHP ENV SuperGlobal in URI |
| T1190 | T1190 (0.6490) | ET WEB_SERVER Possible CVE-2013-0156 Ruby On Rails XML YAML tag with !ruby |
| T1190 | T1190 (1.9655) | ET WEB_SPECIFIC_APPS PithCMS oldnews_reader.php lang Parameter Local File Inclusion Attempt |
| T1190 | T1190 (1.1205) | ET WEB_SERVER PHP Possible https Local File Inclusion Attempt |
| T1190 | T1190 (0.8148) | ETPRO EXPLOIT Possible HP.SSF.WebService Exploit Attempt |
| T1190 | T1190 (2.3262) | ET WEB_SPECIFIC_APPS Joomla 3.7.0 - Sql Injection (CVE-2017-8917) |
| T1190 | T1190 (1.6672) | ET EXPLOIT LastPass RCE Attempt |
| T1190 | T1190 (0.5493) | GPL EXPLOIT /iisadmpwd/aexp2.htr access |
| T1190 | T1190 (1.9801) | ET WEB_SPECIFIC_APPS KR-Web krgourl.php DOCUMENT_ROOT Parameter Remote File Inclusion Attempt |
| T1190 | T1190 (-0.1797) | GPL FTP CWD ~root attempt |
| T1190 | T1190 (1.0471) | ET WEB_SERVER open_basedir PHP config option in uri |
