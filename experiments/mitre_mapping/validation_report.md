# attack_mapper vs. hand-audited sample

- LLM reasoning layer (Layer D): off (NullLLMClient)
- matched audit rows: **500**
- scoreable (non-ambiguous) rows: **397**
- excluded: 103 rows -- of which 12 are tactic-only (`TA####`, unhittable by a technique-predicting pipeline, skipped by design -- see `label_queue/CONVENTION.md`), the rest ambiguous or non-malicious
- top-1 correct vs. hand-audit proposed technique (micro): **151/397 = 38.0%**
- **macro-average** (mean per-technique accuracy, 52 distinct true labels): **18.6%**
- most-predicted technique: T1190 on 53/397 scoreable rows (13.4%) -- a large gap between micro and macro, or a share well above the true base rate, indicates collapse toward the modal class rather than per-rule reasoning
- flagged for human review: 461/500 (92.2%)
- source breakdown (top-1 mapping's source): {'bridge_table': 314, 'tier2_combined': 53, 'embedding': 84, 'declared': 39, 'ioc_alias': 10}
- label provenance: 100 human-confirmed, 400 model-proposed/unconfirmed
- accuracy by label set: hand_audit 43/80 = 53.8%, v2_blind 108/317 = 34.1% -- a large gap between the two suggests labeling drift in the expansion, not a real change in pipeline quality
- ET rule body matched (not just the title): 311/500 (62.2%) -- near 0% means `attack_mapper/data/emerging-all.rules` is stale or absent and the `declared` source cannot fire; the run is degraded, not a baseline
- wall time: 5.3s for 500 rows

**Baseline for comparison** (`archive/tiered_approach/tier2_vs_audit_findings.md`, TF-IDF classifier trained on 26,644-row ET-labeled corpus): 27/79 = 34.2% top-1.

**Coverage caveat**: the brief asks for a 200+-rule labeled regression set. This harness scores 500 rows (397 scoreable), of which **100 are human-confirmed** and 400 are model-proposed labels awaiting review (`label_source`, and the empty `reviewer_verdict` column, mark which is which -- see `label_queue/CONVENTION.md`). Row count alone does not satisfy the bar: an unreviewed label is a hypothesis, not ground truth.

## Miss / skip rows

| proposed | mapper top-1 (source, conf) | verdict | signature |
|---|---|---|---|
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible Qmail CVE-2014-6271 Mail From attempt |
| TA0011 | T1486 (tier2_combined, 0.29) | SKIPPED | ET CNC Ransomware Tracker Reported CnC Server group 101 |
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
| T1210 | T1190 (tier2_combined, 0.28) | MISS | ET EXPLOIT Cisco Smart Install Exploitation Tool - ChangeConfig |
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
| T1203 | T1189 (tier2_combined, 0.33) | MISS | BROWSER-CHROME Google Chrome FileReader use after free attempt |
| T1071.001 | T1105 (tier2_combined, 0.27) | MISS | ET ATTACK_RESPONSE Metasploit Meterpreter Reverse HTTPS certificate |
| T1087.001 | T1105 (tier2_combined, 0.34) | MISS | ET ATTACK_RESPONSE Net User Command Response |
| T1033 | T1592 (bridge_table, 0.40) | MISS | ET ATTACK_RESPONSE Output of id command from HTTP server |
| T1003.008 | T1041 (bridge_table, 0.40) | MISS | ET ATTACK_RESPONSE Possible /etc/passwd via HTTP (linux style) |
| T1189 | T1105 (tier2_combined, 0.26) | MISS | ET ATTACK_RESPONSE Possible BeEF HTTP Headers Inbound |
| T1059.006 | T1059 (tier2_combined, 0.28) | MISS | ET ATTACK_RESPONSE python shell spawn attempt |
| (none) - non-malicious | T1213.005 (embedding, 0.16) | SKIPPED | ET CHAT Facebook Chat using XMPP |
| (none) - non-malicious | T1592 (bridge_table, 0.40) | SKIPPED | ET CHAT Google IM traffic Jabber client sign-on |
| (none) - non-malicious | T1592 (bridge_table, 0.40) | SKIPPED | ET CHAT Google Talk (Jabber) Client Login |
| ambiguous: (none) / T1071.001 | T1518.001 (embedding, 0.15) | SKIPPED | ET CHAT IRC JOIN command |
| ambiguous: (none) / T1071.001 | T1518.001 (embedding, 0.16) | SKIPPED | ET CHAT IRC NICK command |
| ambiguous: (none) / T1071.001 | T1518.001 (embedding, 0.17) | SKIPPED | ET CHAT IRC PRIVMSG command |
| ambiguous: (none) / T1071.001 | T1552.008 (embedding, 0.17) | SKIPPED | ET CHAT IRC USER command |
| ambiguous: (none) / T1071.001 | T1552.008 (embedding, 0.18) | SKIPPED | ET CHAT IRC authorization message |
| (none) - non-malicious | T1565 (bridge_table, 0.70) | SKIPPED | ET CHAT MSN status change |
| (none) - non-malicious | T1552.008 (embedding, 0.15) | SKIPPED | ET CHAT Skype User-Agent detected |
| (none) - non-malicious | T1046 (embedding, 0.16) | SKIPPED | ET CHAT Skype VOIP Checking Version (Startup) |
| TA0011 | T1078 (tier2_combined, 0.29) | SKIPPED | ET CINS Active Threat Intelligence Poor Reputation IP group 100 |
| TA0011 | T1592 (bridge_table, 0.40) | SKIPPED | ET CINS Active Threat Intelligence Poor Reputation IP group 44 |
| TA0011 | T1078 (tier2_combined, 0.28) | SKIPPED | ET CINS Active Threat Intelligence Poor Reputation IP group 66 |
| TA0011 | T1078 (tier2_combined, 0.28) | SKIPPED | ET CINS Active Threat Intelligence Poor Reputation IP group 91 |
| TA0011 | T1190 (embedding, 0.19) | SKIPPED | ET COMPROMISED Known Compromised or Hostile Host Traffic group 9 |
| T1498 | T1499 (bridge_table, 0.70) | MISS | ET CURRENT_EVENTS Likely Linux/Xorddos DDoS Attack Participation (xxxatat456.com) |
| T1190 | T1595.002 (bridge_table, 0.70) | MISS | ET CURRENT_EVENTS Malformed HeartBeat Request |
| T1189 | T1104 (embedding, 0.14) | MISS | ET CURRENT_EVENTS Nuclear EK Landing Apr 03 2015 |
| T1189 | T1104 (embedding, 0.15) | MISS | ET CURRENT_EVENTS Nuclear EK Landing Apr 22 2015 |
| T1189 | T1105 (bridge_table, 0.40) | MISS | ET CURRENT_EVENTS Possible Magnitude IE EK Payload Nov 8 2013 |
| T1190 | T1041 (tier2_combined, 0.26) | MISS | ET CURRENT_EVENTS Possible OpenSSL HeartBleed Large HeartBeat Response (Client Init Vuln Server) |
| T1190 | T1041 (tier2_combined, 0.27) | MISS | ET CURRENT_EVENTS Possible OpenSSL HeartBleed Large HeartBeat Response (Server Init Vuln Client) |
| T1190 | T1552.004 (embedding, 0.14) | MISS | ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 3 (Inbound to Common SSL Port) |
| T1190 | T1552.004 (embedding, 0.13) | MISS | ET CURRENT_EVENTS Possible TLS HeartBleed Unencrypted Request Method 4 (Inbound to Common SSL Port) |
| T1190 | T1041 (bridge_table, 0.40) | MISS | ET CURRENT_EVENTS Possible ZyXELs ZynOS Configuration Download Attempt (Contains Passwords) |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET CURRENT_EVENTS QNAP Shellshock CVE-2014-6271 |
| T1105 | T1203 (bridge_table, 0.40) | MISS | ET CURRENT_EVENTS Unknown Malicious Second Stage Download URI Struct M2 Feb 06 2015 |
| T1105 | T1203 (bridge_table, 0.40) | MISS | ET CURRENT_EVENTS Unknown Malicious Second Stage Download URI Struct Sept 15 2015 |
| ambiguous: TA0011 / T1071.004 | T1518.001 (embedding, 0.22) | SKIPPED | ET DNS Query for .su TLD (Soviet Union) Often Malware Related |
| ambiguous: TA0011 / T1071.004 | T1046 (embedding, 0.19) | SKIPPED | ET DNS Query to a *.pw domain - Likely Hostile |
| ambiguous: TA0011 / T1071.004 | T1046 (embedding, 0.19) | SKIPPED | ET DNS Query to a .tk domain - Likely Hostile |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS Catalyst memory leak attack |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS Cisco 4200 Wireless Lan Controller Long Authorisation Denial of Service Attempt |
| T1498.002 | T1498 (bridge_table, 0.70) | MISS | ET DOS DNS Amplification Attack Possible Outbound Windows Non-Recursive Root Hint Reserved Port |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS ICMP Path MTU lowered below acceptable threshold |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS LibuPnP CVE-2012-5963 ST UDN Buffer Overflow |
| T1498.002 | T1498 (bridge_table, 0.70) | MISS | ET DOS Likely NTP DDoS In Progress PEER_LIST_SUM Response to Non-Ephemeral Port IMPL 0x02 |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS Microsoft Windows 7 ICMPv6 Router Advertisement Flood |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS Miniupnpd M-SEARCH Buffer Overflow CVE-2013-0229 |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS Netgear DG632 Web Management Denial Of Service Attempt |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS NetrWkstaUserEnum Request with large Preferred Max Len |
| T1498 | T1499 (bridge_table, 0.70) | MISS | ET DOS Outbound Low Orbit Ion Cannon LOIC Tool Internal User May Be Participating in DDOS |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS Possible Cisco ASA 5500 Series Adaptive Security Appliance Remote SIP Inspection Device Reload Denial of Service Attempt |
| T1498.002 | T1498 (bridge_table, 0.70) | MISS | ET DOS Possible Memcached DDoS Amplification Query (set) |
| T1498.002 | T1498 (bridge_table, 0.70) | MISS | ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x02 |
| T1498.002 | T1498 (bridge_table, 0.70) | MISS | ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests IMPL 0x03 |
| ambiguous: T1595 / T1498.002 | T1498 (bridge_table, 0.70) | SKIPPED | ET DOS Possible SSDP Amplification Scan in Progress |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS Possible VNC ClientCutText Message Denial of Service/Memory Corruption Attempt |
| T1498.002 | T1498 (bridge_table, 0.70) | MISS | ET DOS Potential Inbound NTP denial-of-service attempt (repeated mode 7 reply) |
| T1498.002 | T1498 (bridge_table, 0.70) | MISS | ET DOS Potential Inbound NTP denial-of-service attempt (repeated mode 7 request) |
| T1498 | T1499 (bridge_table, 0.70) | MISS | ET DOS Trojan.BlackRev V1.Botnet HTTP Login POST Flood Traffic Inbound |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS ntop Basic-Auth DOS inbound |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET DOS ntop Basic-Auth DOS outbound |
| T1190 | T1499 (bridge_table, 0.70) | MISS | ET EXPLOIT FortiOS SSL VPN - Pre-Auth Messages Payload Buffer Overflow (CVE-2018-13381) |
| ambiguous: T1027 / T1203 | T1203 (bridge_table, 0.40) | SKIPPED | ET EXPLOIT Metasploit Random Base CharCode JS Encoded String |
| T1203 | T1082 (declared, 1.00) | MISS | ET EXPLOIT Possible Internet Explorer VBscript failure to handle error case information disclosure CVE-2014-6332 Common Construct M2 |
| T1190 | T1068 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible MySQL cnf overwrite CVE-2016-6662 Attempt |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible OpenVPN CVE-2014- 6271 attempt |
| T1190 | T1210 (bridge_table, 0.70) | MISS | ET EXPLOIT Possible OpenVPN CVE-2014-6271 attempt |
| T1190 | T1210 (bridge_table, 0.70) | MISS | ET EXPLOIT Possible Palo Alto SSL VPN sslmgr Format String Vulnerability (Inbound) |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible Postfix CVE-2014-6271 attempt |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible Pure-FTPd CVE-2014-6271 attempt |
| T1187 | T1190 (tier2_combined, 0.30) | MISS | ET EXPLOIT Possible Redirect to SMB exploit attempt - 303 |
| T1190 | T1210 (tier2_combined, 0.31) | MISS | ET EXPLOIT Possible SpamAssassin Milter Plugin Remote Arbitrary Command Injection Attempt |
| T1190 | T1041 (bridge_table, 0.40) | MISS | ET EXPLOIT Possible ZyXELs ZynOS Configuration Download Attempt (Contains Passwords) |
| T1105 | T1046 (embedding, 0.20) | MISS | ET EXPLOIT QNAP Shellshock script retrieval |
| ambiguous: T1190 / T1098.004 | T1068 (bridge_table, 0.40) | SKIPPED | ET EXPLOIT REDIS Attempted SSH Key Upload |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Seagate Business NAS Unauthenticated Remote Command Execution |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET EXPLOIT Serialized Java Object Calling Common Collection Function |
| T1190 | T1098 (bridge_table, 0.70) | MISS | ET FTP Suspicious Quotation Mark Usage in FTP Username |
| ambiguous: T1110 / T1021.004 | T1592 (bridge_table, 0.40) | SKIPPED | ET INFO NetSSH SSH Version String Hardcoded in Metasploit |
| T1036.008 | T1057 (embedding, 0.20) | MISS | ET INFO Possible Windows executable sent when remote host claims to send a Text File |
| T1105 | T1041 (bridge_table, 0.40) | MISS | ET INFO SUSPICIOUS Dotted Quad Host MZ Response |
| ambiguous: (none) / T1557 | T1041 (bridge_table, 0.40) | SKIPPED | ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel |
| (none) - non-malicious | T1592 (bridge_table, 0.40) | SKIPPED | ET INFO Windows OS Submitting USB Metadata to Microsoft |
| T1071.001 | T1518.001 (embedding, 0.20) | MISS | ET MALWARE Common Adware Library ISX User Agent Detected |
| T1071.001 | T1041 (tier2_combined, 0.30) | MISS | ET MALWARE W32/OpenCandy Adware Checkin |
| T1071.001 | T1041 (declared, 1.00) | MISS | ET MOBILE_MALWARE Android/Code4hk.A Checkin |
| (none) - non-malicious | T1105 (bridge_table, 0.40) | SKIPPED | ET P2P BitTorrent DHT nodes reply |
| (none) - non-malicious | T1105 (bridge_table, 0.40) | SKIPPED | ET P2P BitTorrent DHT ping request |
| (none) - non-malicious | T1041 (bridge_table, 0.40) | SKIPPED | ET P2P BitTorrent peer sync |
| (none) - non-malicious | T1105 (bridge_table, 0.40) | SKIPPED | ET P2P Bittorrent P2P Client User-Agent (Transmission/1.x) |
| ambiguous: (none) / T1090.003 | T1016.001 (embedding, 0.21) | SKIPPED | ET P2P TOR 1.0 Outbound Circuit Traffic |
| (none) - non-malicious | T1518.001 (embedding, 0.19) | SKIPPED | ET POLICY Application Crash Report Sent to Microsoft |
| (none) - non-malicious | T1016 (embedding, 0.19) | SKIPPED | ET POLICY Cisco Device in Config Mode |
| (none) - non-malicious | T1553.003 (embedding, 0.14) | SKIPPED | ET POLICY Cleartext WordPress Login |
| (none) - non-malicious | T1590.002 (embedding, 0.20) | SKIPPED | ET POLICY DNS Query For XXX Adult Site Top Level Domain |
| ambiguous: (none) / T1584.002 | T1565 (bridge_table, 0.70) | SKIPPED | ET POLICY DNS Update From External net |
| (none) - non-malicious | T1041 (bridge_table, 0.40) | SKIPPED | ET POLICY Dropbox Client Broadcasting |
| (none) - non-malicious | T1041 (bridge_table, 0.40) | SKIPPED | ET POLICY Dropbox DNS Lookup - Possible Offsite File Backup in Use |
| ambiguous: (none) / T1567.002 | T1041 (bridge_table, 0.40) | SKIPPED | ET POLICY Dropbox.com Offsite File Backup in Use |
| ambiguous: (none) / T1016 | T1592 (bridge_table, 0.40) | SKIPPED | ET POLICY DynDNS CheckIp External IP Address Server Response |
| ambiguous: (none) / T1105 | T1105 (tier2_combined, 0.33) | SKIPPED | ET POLICY Executable and linking format (ELF) file download |
| ambiguous: (none) / T1105 | T1105 (tier2_combined, 0.29) | SKIPPED | ET POLICY Executable and linking format (ELF) file download Over HTTP |
| ambiguous: (none) / T1105 | T1105 (bridge_table, 0.40) | SKIPPED | ET POLICY Executable served from Amazon S3 |
| (none) - non-malicious | T1049 (embedding, 0.18) | SKIPPED | ET POLICY External Unencrypted Connection to BASE Console |
| (none) - non-malicious | T1071.001 (tier2_combined, 0.26) | SKIPPED | ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management |
| (none) - non-malicious | T1195.001 (embedding, 0.17) | SKIPPED | ET POLICY GNU/Linux YUM User-Agent Outbound likely related to package management |
| ambiguous: TA0011 / T1071.001 | T1518.001 (embedding, 0.19) | SKIPPED | ET POLICY HTTP Request to a *.tk domain |
| ambiguous: (none) / T1571 | T1071.001 (embedding, 0.18) | SKIPPED | ET POLICY HTTP traffic on port 443 (POST) |
| (none) - non-malicious | T1552.006 (embedding, 0.12) | SKIPPED | ET POLICY Http Client Body contains pass= in cleartext |
| (none) - non-malicious | T1003.007 (embedding, 0.15) | SKIPPED | ET POLICY Http Client Body contains passwd= in cleartext |
| ambiguous: (none) / T1016 | T1592 (bridge_table, 0.40) | SKIPPED | ET POLICY IP Check Domain (icanhazip. com in HTTP Host) |
| ambiguous: (none) / T1016 | T1592 (bridge_table, 0.40) | SKIPPED | ET POLICY IP Check Domain (whatismyip in HTTP Host) |
| (none) - non-malicious | T1003.007 (embedding, 0.17) | SKIPPED | ET POLICY Incoming Basic Auth Base64 HTTP Password detected unencrypted |
| T1021.001 | T1068 (bridge_table, 0.40) | MISS | ET POLICY MS Terminal Server Root login |
| (none) - non-malicious | T1497.001 (embedding, 0.16) | SKIPPED | ET POLICY Metasploit Framework Checking For Update |
| (none) - non-malicious | T1049 (embedding, 0.17) | SKIPPED | ET POLICY OpenVPN Update Check |
| T1571 | T1041 (bridge_table, 0.40) | MISS | ET POLICY Outbound MSSQL Connection to Non-Standard Port - Likely Malware |
| (none) - non-malicious | T1190 (embedding, 0.18) | SKIPPED | ET POLICY Outdated Flash Version M1 |
| (none) - non-malicious | T1190 (embedding, 0.16) | SKIPPED | ET POLICY Outdated Flash Version M2 |
| (none) - non-malicious | T1003.007 (embedding, 0.16) | SKIPPED | ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted |
| ambiguous: (none) / T1204.002 | T1105 (bridge_table, 0.40) | SKIPPED | ET POLICY PDF With Embedded File |
| ambiguous: (none) / T1105 | T1105 (bridge_table, 0.40) | SKIPPED | ET POLICY PE EXE or DLL Windows file download HTTP |
| T1595 | T1592 (bridge_table, 0.40) | MISS | ET POLICY POSSIBLE Web Crawl using Curl |
| T1595 | T1592 (bridge_table, 0.40) | MISS | ET POLICY POSSIBLE Web Crawl using Wget |
| T1016.001 | T1592 (bridge_table, 0.40) | MISS | ET POLICY Possible IP Check api.ipify.org |
| ambiguous: (none) / TA0043 | T1016 (embedding, 0.17) | SKIPPED | ET POLICY Possible Kali Linux hostname in DHCP Request Packet |
| T1021.002 | T1570 (tier2_combined, 0.38) | MISS | ET POLICY Powershell Activity Over SMB - Likely Lateral Movement |
| T1021.002 | T1570 (declared, 1.00) | MISS | ET POLICY Powershell Command With Hidden Window Argument Over SMB - Likely Lateral Movement |
| T1021.002 | T1570 (declared, 1.00) | MISS | ET POLICY Powershell Command With No Profile Argument Over SMB - Likely Lateral Movement |
| T1021.002 | T1570 (declared, 1.00) | MISS | ET POLICY Powershell Command With NonInteractive Argument Over SMB - Likely Lateral Movement |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET POLICY Proxy TRACE Request - inbound |
| ambiguous: (none) / T1595 | T1071.001 (tier2_combined, 0.28) | SKIPPED | ET POLICY Python-urllib/ Suspicious User Agent |
| T1570 | T1041 (bridge_table, 0.40) | MISS | ET POLICY SMB Executable File Transfer |
| T1053.002 | T1041 (bridge_table, 0.40) | MISS | ET POLICY SMB Remote AT Scheduled Job Pipe Creation |
| T1570 | T1105 (bridge_table, 0.40) | MISS | ET POLICY SMB2 NT Create AndX Request For a Powershell .ps1 File |
| T1570 | T1105 (bridge_table, 0.40) | MISS | ET POLICY SMB2 NT Create AndX Request For an Executable File |
| T1053.002 | T1041 (bridge_table, 0.40) | MISS | ET POLICY SMB2 Remote AT Scheduled Job Create Request |
| (none) - non-malicious | T1518.001 (embedding, 0.20) | SKIPPED | ET POLICY SSLv3 inbound connection to server vulnerable to POODLE attack |
| (none) - non-malicious | T1518.001 (embedding, 0.19) | SKIPPED | ET POLICY SSLv3 outbound connection from client vulnerable to POODLE attack |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET POLICY Suspicious inbound to MSSQL port 1433 |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET POLICY Suspicious inbound to Oracle SQL port 1521 |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET POLICY Suspicious inbound to PostgreSQL port 5432 |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET POLICY Suspicious inbound to mSQL port 4333 |
| T1219 | T1592 (bridge_table, 0.40) | MISS | ET POLICY TeamViewer Dyngate User-Agent |
| (none) - non-malicious | T1071.001 (tier2_combined, 0.25) | SKIPPED | ET POLICY User-Agent (Launcher) |
| ambiguous: (none) / T1105 | T1518.001 (embedding, 0.21) | SKIPPED | ET POLICY User-Agent (NSIS_Inetc (Mozilla)) - Sometimes used by hostile installers |
| (none) - non-malicious | T1190 (embedding, 0.18) | SKIPPED | ET POLICY Vulnerable Java Version 1.7.x Detected |
| (none) - non-malicious | T1105 (bridge_table, 0.40) | SKIPPED | ET POLICY curl User-Agent Outbound |
| (none) - non-malicious | T1071.001 (tier2_combined, 0.26) | SKIPPED | ET POLICY libwww-perl User-Agent |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Amap TCP Service Scan Detected |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Amap UDP Service Scan Detected |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET SCAN Apache mod_deflate DoS via many multiple byte Range values |
| T1595.002 | T1190 (bridge_table, 0.70) | MISS | ET SCAN Apache mod_proxy Reverse Proxy Exposure 1 |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Behavioral Unusually fast Terminal Server Traffic Potential Scan or Infection (Inbound) |
| T1595.002 | T1210 (declared, 1.00) | MISS | ET SCAN COMMIX Command injection scan attempt |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Cisco Torch TFTP Scan |
| T1595.002 | T1190 (bridge_table, 0.70) | MISS | ET SCAN DEBUG Method Request with Command |
| T1595.003 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN DirBuster Scan in Progress |
| T1595.003 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN DirBuster Web App Scan in Progress |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Grim's Ping ftp scanning tool |
| T1018 | T1110 (bridge_table, 0.70) | MISS | ET SCAN ICMP PING IPTools |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Modbus Scanning detected |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Modified Sipvicious User-Agent Detected (sundayddr) |
| T1018 | T1016 (ioc_alias, 0.75) | MISS | ET SCAN NBTStat Query Response to External Destination, Possible Windows Network Enumeration |
| ambiguous: T1046 / T1018 | T1016 (ioc_alias, 0.75) | SKIPPED | ET SCAN NMAP -f -sXET SCAN Multiple NBTStat Query Responses to External Destination, Possible Automated Windows Network Enumeration |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN NMAP -sO |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN NMAP -sS window 2048 |
| T1595 | T1046 (bridge_table, 0.70) | MISS | ET SCAN NMAP OS Detection Probe |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN NMAP SIP Version Detect OPTIONS Scan |
| ambiguous: T1190 / (none) | T1190 (tier2_combined, 0.29) | SKIPPED | ET SCAN NNG MS02-039 Exploit False Positive Generator - May Conceal A Genuine Attack |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET SCAN Nessus FTP Scan detected (ftp_anonymous.nasl) |
| T1595.002 | T1046 (bridge_table, 0.70) | MISS | ET SCAN Nessus FTP Scan detected (ftp_writeable_directories.nasl) |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET SCAN Netsparker Scan in Progress |
| T1595 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE) |
| T1046 | T1592 (bridge_table, 0.40) | MISS | ET SCAN Non-Allowed Host Tried to Connect to MySQL Server |
| (none) - non-malicious | T1018 (bridge_table, 0.70) | SKIPPED | ET SCAN Non-Malicious SSH/SSL Scanner on the run |
| (none) - non-malicious | T1592 (bridge_table, 0.40) | SKIPPED | ET SCAN PRO Search Crawler Probe |
| T1595 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Possible Nmap User-Agent Observed |
| T1595.002 | T1190 (ioc_alias, 0.75) | MISS | ET SCAN Possible SQLMAP Scan |
| T1046 | T1041 (bridge_table, 0.40) | MISS | ET SCAN Potential SSH Scan OUTBOUND |
| T1190 | T1068 (bridge_table, 0.40) | MISS | ET SCAN Redis SSH Key Overwrite Probing |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET SCAN SFTP/FTP Password Exposure via sftp-config.json |
| T1046 | T1018 (bridge_table, 0.70) | MISS | ET SCAN Sipvicious Scan |
| T1595.002 | T1190 (declared, 1.00) | MISS | ET SCAN Sqlmap SQL Injection Scan |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN Suspicious inbound to MSSQL port 1433 |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN Suspicious inbound to Oracle SQL port 1521 |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN Suspicious inbound to PostgreSQL port 5432 |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN Suspicious inbound to mSQL port 4333 |
| T1046 | T1595.002 (bridge_table, 0.70) | MISS | ET SCAN Suspicious inbound to mySQL port 3306 |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET SCAN Unusually Fast 400 Error Messages (Bad Request), Possible Web Application Scan |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET SCAN Unusually Fast 403 Error Messages, Possible Web Application Scan |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET SCAN Unusually Fast 404 Error Messages (Page Not Found), Possible Web Application Scan/Directory Guessing Attack |
| T1602.002 | T1592 (bridge_table, 0.40) | MISS | ET SNMP Attempt to retrieve Cisco Config via TFTP (CISCO-CONFIG-COPY) |
| T1078.001 | T1210 (bridge_table, 0.70) | MISS | ET SNMP Attempted UDP Access Attempt to Cisco IOS 12.1 Hidden Read/Write Community String ILMI |
| T1078.001 | T1210 (bridge_table, 0.70) | MISS | ET SNMP Samsung Printer SNMP Hardcode RW Community String |
| T1078.001 | T1210 (bridge_table, 0.70) | MISS | ET SNMP missing community string attempt 1 |
| ambiguous: (none) / T1105 | T1041 (bridge_table, 0.40) | SKIPPED | ET TFTP Outbound TFTP Error Message |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 128 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 155 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 271 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 285 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 328 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 519 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 595 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 615 |
| T1090.003 | T1016.001 (embedding, 0.20) | MISS | ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 684 |
| T1083 | T1041 (bridge_table, 0.40) | MISS | ET TROJAN ATTACKER IRCBot - PRIVMSG Response - Directory Listing |
| T1083 | T1041 (bridge_table, 0.40) | MISS | ET TROJAN ATTACKER IRCBot - PRIVMSG Response - Directory Listing *nix |
| T1087 | T1041 (bridge_table, 0.40) | MISS | ET TROJAN ATTACKER IRCBot - PRIVMSG Response - net command output |
| T1059 | T1041 (bridge_table, 0.40) | MISS | ET TROJAN ATTACKER IRCBot - The command completed successfully - PRIVMSG Response |
| TA0011 | T1041 (tier2_combined, 0.29) | SKIPPED | ET TROJAN Backdoor family PCRat/Gh0st CnC traffic (OUTBOUND) 106 |
| TA0011 | T1498 (bridge_table, 0.70) | SKIPPED | ET TROJAN DDoS.XOR Checkin |
| ambiguous: TA0011 / T1071.001 | T1041 (tier2_combined, 0.27) | SKIPPED | ET TROJAN Double HTTP/1.1 Header Inbound - Likely Hostile Traffic |
| T1205 | T1219 (embedding, 0.18) | MISS | ET TROJAN HackerDefender Root Kit Remote Connection Attempt Detected |
| TA0011 | T1041 (tier2_combined, 0.26) | SKIPPED | ET TROJAN Miuref/Boaxxe Checkin |
| T1071 | T1518.001 (embedding, 0.17) | MISS | ET TROJAN NgrBot IRC CnC Channel Join |
| ambiguous: T1203 / T1105 | T1007 (embedding, 0.19) | SKIPPED | ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server) |
| TA0011 | T1041 (tier2_combined, 0.26) | SKIPPED | ET TROJAN Possible NanoCore C2 60B |
| TA0011 | T1041 (tier2_combined, 0.26) | SKIPPED | ET TROJAN Possible NanoCore C2 64B |
| T1071 | T1518.001 (embedding, 0.16) | MISS | ET TROJAN Possible Zendran ELF IRCBot Joining Channel 2 |
| TA0011 | T1518.001 (embedding, 0.21) | SKIPPED | ET TROJAN Poweliks Clickfraud CnC M4 |
| ambiguous: TA0011 / T1105 | T1036.003 (embedding, 0.15) | SKIPPED | ET TROJAN Unknown - Loader - Check .exe Updated |
| T1082 | T1007 (embedding, 0.20) | MISS | ET TROJAN Windows WMIC COMPUTERSYSTEM get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1087 | T1007 (embedding, 0.20) | MISS | ET TROJAN Windows WMIC NETLOGIN get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1016 | T1047 (embedding, 0.20) | MISS | ET TROJAN Windows WMIC NIC get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1082 | T1047 (embedding, 0.20) | MISS | ET TROJAN Windows WMIC OS get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1057 | T1047 (embedding, 0.21) | MISS | ET TROJAN Windows WMIC PROCESS get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1082 | T1047 (embedding, 0.21) | MISS | ET TROJAN Windows WMIC SERVER get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1007 | T1047 (embedding, 0.21) | MISS | ET TROJAN Windows WMIC SERVICE get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1135 | T1047 (embedding, 0.20) | MISS | ET TROJAN Windows WMIC SHARE get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1082 | T1047 (embedding, 0.19) | MISS | ET TROJAN Windows WMIC STARTUP get Microsoft Windows DOS prompt command exit OUTBOUND |
| T1083 | T1518.001 (embedding, 0.19) | MISS | ET TROJAN Windows dir Microsoft Windows DOS prompt command exit OUTBOUND |
| T1082 | T1652 (embedding, 0.20) | MISS | ET TROJAN Windows driverquery -si Microsoft Windows DOS prompt command exit OUTBOUND |
| T1082 | T1652 (embedding, 0.20) | MISS | ET TROJAN Windows driverquery -v Microsoft Windows DOS prompt command exit OUTBOUND |
| T1615 | T1518.001 (embedding, 0.19) | MISS | ET TROJAN Windows gpresult Microsoft Windows DOS prompt command exit OUTBOUND |
| T1018 | T1016 (ioc_alias, 0.75) | MISS | ET TROJAN Windows nbtstat -a Microsoft Windows DOS prompt command exit OUTBOUND |
| T1049 | T1016 (ioc_alias, 0.75) | MISS | ET TROJAN Windows nbtstat -s Microsoft Windows DOS prompt command exit OUTBOUND |
| T1033 | T1518.001 (embedding, 0.19) | MISS | ET TROJAN Windows quser Microsoft Windows DOS prompt command exit OUTBOUND |
| T1033 | T1202 (embedding, 0.18) | MISS | ET TROJAN Windows qwinsta Microsoft Windows DOS prompt command exit OUTBOUND |
| T1189 | T1526 (embedding, 0.17) | MISS | ET WEB_CLIENT BeEF Cookie Outbound |
| T1027 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT Hex Obfuscation of Script Tag % Encoding |
| T1027 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT Hex Obfuscation of String.fromCharCode % Encoding |
| T1027 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT Hex Obfuscation of charCodeAt % Encoding |
| T1027 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT Hex Obfuscation of document.write % Encoding |
| T1027 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT Hex Obfuscation of substr % Encoding |
| T1027 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT Hex Obfuscation of unescape % Encoding |
| T1059.001 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT PowerShell call in script 1 |
| T1059.001 | T1203 (bridge_table, 0.40) | MISS | ET WEB_CLIENT PowerShell call in script 2 |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt |
| T1003.008 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER /etc/shadow Detected in URI |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER /system32/ in Uri - Possible Protected Directory Access Attempt |
| T1505.003 | T1105 (bridge_table, 0.40) | MISS | ET WEB_SERVER 401TRG Generic Webshell Request - POST with wget in body |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Access to /phppath/php Possible Plesk 0-day Exploit June 05 2013 |
| T1190 | T1068 (bridge_table, 0.40) | MISS | ET WEB_SERVER Attempt To Access MSSQL xp_cmdshell Stored Procedure Via URI |
| T1190 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER ColdFusion componentutils access |
| T1552.001 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER ColdFusion password.properties access |
| T1190 | T1083 (declared, 1.00) | MISS | ET WEB_SERVER Coldfusion cfcexplorer Directory Traversal |
| T1190 | T1082 (declared, 1.00) | MISS | ET WEB_SERVER DD-WRT Information Disclosure Attempt |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Exploit Suspected PHP Injection Attack (cmd=) |
| ambiguous: (none) / T1190 | T1190 (tier2_combined, 0.30) | SKIPPED | ET WEB_SERVER HTTP 414 Request URI Too Large |
| T1595.003 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER IIS 8.3 Filename With Wildcard (Possible File/Dir Bruteforce) |
| T1190 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER Joomla Component SQLi Attempt |
| T1190 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER Likely Malicious Request for /proc/self/environ |
| T1190 | T1565 (bridge_table, 0.70) | MISS | ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Onmouseover= in URI - Likely Cross Site Scripting Attempt |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP Easteregg Information-Disclosure (funny-logo) |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP Easteregg Information-Disclosure (php-logo) |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP Easteregg Information-Disclosure (phpinfo) |
| T1595.002 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP Easteregg Information-Disclosure (zend-logo) |
| T1190 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP REQUEST SuperGlobal in URI |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP System Command in HTTP POST |
| T1190 | T1105 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP tags in HTTP POST |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER PHP.//Input in HTTP POST |
| T1190 | T1592 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible Attempt to Get SQL Server Version in URI using SELECT VERSION |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible CVE-2014-6271 Attempt |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Cookie |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Version Number |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers |
| T1499 | T1498 (bridge_table, 0.70) | MISS | ET WEB_SERVER Possible Cherokee Web Server GET AUX Request Denial Of Service Attempt |
| T1499 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible IIS Integer Overflow DoS (CVE-2015-1635) |
| T1190 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible MySQL SQLi Attempt Information Schema Access |
| T1190 | T1565 (bridge_table, 0.70) | MISS | ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM |
| T1190 | T1565 (bridge_table, 0.70) | MISS | ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT |
| T1190 | T1068 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible SQLi xp_cmdshell POST body |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY. |
| T1190 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt |
| T1190 | T1565 (bridge_table, 0.70) | MISS | ET WEB_SERVER Suspicious Chmod Usage in URI |
| T1190 | T1041 (bridge_table, 0.40) | MISS | ET WEB_SERVER Tilde in URI - potential .php~ source disclosure vulnerability |
| T1595.002 | T1203 (bridge_table, 0.40) | MISS | ET WEB_SERVER WEB-PHP phpinfo access |
| T1190 | T1105 (bridge_table, 0.40) | MISS | ET WEB_SERVER WGET Command Specifying Output in HTTP Headers |
| T1505.003 | T1105 (bridge_table, 0.40) | MISS | ET WEB_SERVER WebShell Generic - wget http - POST |
| T1190 | T1199 (bridge_table, 0.70) | MISS | ET WEB_SPECIFIC_APPS BLOG CMS nsextt parameter Cross Site Scripting Vulnerability |

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
| T1190 | T1190 (tier2_combined, 0.31) | ETPRO EXPLOIT Possible Jetty Web Server Information Leak Attempt |
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
| T1190 | T1190 (tier2_combined, 0.37) | ETPRO EXPLOIT Possible HP.SSF.WebService Exploit Attempt |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Medusa User-Agent |
| T1105 | T1105 (bridge_table, 0.40) | ET CURRENT_EVENTS Terse alphanumeric executable downloader high likelihood of being hostile |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS Joomla 3.7.0 - Sql Injection (CVE-2017-8917) |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Possible MYSQL GeomFromWKB() function Denial Of Service Attempt |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN PHP Attack Tool Morfeus F Scanner |
| T1190 | T1190 (tier2_combined, 0.41) | ET EXPLOIT LastPass RCE Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS KR-Web krgourl.php DOCUMENT_ROOT Parameter Remote File Inclusion Attempt |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Microsoft Remote Desktop (RDP) Syn then Reset 30 Second DoS Attempt |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Microsoft Streaming Server Malformed Request |
| T1046 | T1046 (bridge_table, 0.70) | GPL POLICY PCAnywhere server response |
| T1190 | T1190 (tier2_combined, 0.37) | ET WEB_SERVER open_basedir PHP config option in uri |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Excessive SMTP MAIL-FROM DDoS |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Cisco Router HTTP DoS |
| T1203 | T1203 (bridge_table, 0.40) | BROWSER-CHROME Apple Safari/Google Chrome Webkit memory corruption attempt |
| T1499 | T1499 (bridge_table, 0.70) | BROWSER-CHROME V8 JavaScript engine Out-of-Memory denial of service attempt |
| T1110 | T1110 (bridge_table, 0.70) | ET ATTACK_RESPONSE Frequent HTTP 401 Unauthorized - Possible Brute Force Attack |
| T1105 | T1105 (bridge_table, 0.40) | ET CURRENT_EVENTS SUSPICIOUS Firesale gTLD EXE DL with no Referer June 13 2016 |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Cisco 514 UDP flood DoS |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS FreeBSD NFS RPC Kernel Panic |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS HOIC with booster inbound |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS HTTP GET AAAAAAAA Likely FireFlood |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS IBM DB2 kuddb2 Remote Denial of Service Attempt |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS IBM Tivoli Endpoint Buffer Overflow Attempt |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds Integer indef DoS Attempt |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Microsoft Remote Desktop Protocol (RDP) maxChannelIds Negative Integer indef DoS Attempt |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Microsoft Windows LSASS Remote Memory Corruption (CVE-2017-0004) |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Possible MYSQL SELECT WHERE to User Variable Denial Of Service AttemptET DOS Possible MySQL ALTER DATABASE Denial Of Service Attempt |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Possible SMBLoris NBSS Length Mem Exhaustion Vuln Inbound |
| T1499 | T1499 (bridge_table, 0.70) | ET DOS Possible SolarWinds TFTP Server Read Request Denial Of Service Attempt |
| T1498 | T1498 (bridge_table, 0.70) | ET DOS Potential Tsunami SYN Flood Denial Of Service Attempt |
| T1190 | T1190 (tier2_combined, 0.31) | ET EXPLOIT Cisco Smart Install Exploitation Tool - GetConfig |
| T1190 | T1190 (declared, 1.00) | ET EXPLOIT FortiOS SSL VPN - Remote Code Execution (CVE-2018-13383) |
| T1190 | T1190 (tier2_combined, 0.44) | ET EXPLOIT IBM WebSphere - RCE Java Deserialization |
| T1190 | T1190 (tier2_combined, 0.38) | ET EXPLOIT Possible CVE-2014-3704 Drupal SQLi attempt URLENCODE 1 |
| T1068 | T1068 (bridge_table, 0.40) | ET EXPLOIT Possible GoldenPac Priv Esc in-use |
| T1203 | T1203 (bridge_table, 0.40) | ET EXPLOIT Possible iOS Pegasus Safari Exploit (CVE-2016-4657) |
| T1203 | T1203 (bridge_table, 0.40) | ET EXPLOIT Potential Internet Explorer Use After Free CVE-2013-3163 Exploit URI Struct 1 |
| T1190 | T1190 (declared, 1.00) | ET EXPLOIT SolusVM 1.13.03 SQL injection |
| T1190 | T1190 (tier2_combined, 0.31) | ET EXPLOIT TrendMicro node.js HTTP RCE Exploit Inbound (openUrlInDefaultBrowser) |
| T1105 | T1105 (tier2_combined, 0.27) | ET INFO Executable Download from dotted-quad Host |
| T1071.001 | T1071.001 (tier2_combined, 0.27) | ET MALWARE Suspicious User-Agent (1 space) |
| T1105 | T1105 (bridge_table, 0.40) | ET POLICY Possible HTA Application Download |
| T1021.001 | T1021.001 (tier2_combined, 0.27) | ET POLICY RDP connection confirm |
| T1570 | T1570 (declared, 1.00) | ET POLICY SMB2 NT Create AndX Request For a DLL File - Possible Lateral Movement |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Behavioral Unusual Port 137 traffic Potential Scan or Infection |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Behavioral Unusual Port 139 traffic Potential Scan or Infection |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Behavioral Unusual Port 1433 traffic Potential Scan or Infection |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Behavioral Unusual Port 1434 traffic Potential Scan or Infection |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN DominoHunter Security Scan in Progress |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Grendel-Scan Web Application Security Scan Detected |
| T1190 | T1190 (declared, 1.00) | ET SCAN Havij SQL Injection Tool User-Agent Inbound |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Hydra User-Agent |
| T1018 | T1018 (bridge_table, 0.70) | ET SCAN ICMP =XXXXXXXX Likely Precursor to Scan |
| T1018 | T1018 (bridge_table, 0.70) | ET SCAN ICMP Delphi Likely Precursor to Scan |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN MYSQL 4.1 brute force root login attempt |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Metasploit WMAP GET len 0 and type |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Multiple FTP Administrator Login Attempts from Single Source - Possible Brute Force Attempt |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Multiple FTP Root Login Attempts from Single Source - Possible Brute Force Attempt |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Multiple MySQL Login Failures Possible Brute Force Attempt |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN NMAP SIP Version Detection Script Activity |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN NMAP SQL Spider Scan |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Nessus User Agent |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Nikto Web App Scan in Progress |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Nmap NSE Heartbleed Request |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Nmap NSE Heartbleed Response |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Possible Fast-Track Tool Spidering User-Agent Detected |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Possible Scanning for Vulnerable JBoss |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Potential FTP Brute-Force attempt response |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Potential SSH Scan |
| T1046 | T1046 (bridge_table, 0.70) | ET SCAN Potential VNC Scan 5900-5920 |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Potential muieblackcat scanner double-URI and HTTP library |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Rapid IMAP Connections - Possible Brute Force Attack |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Rapid IMAPS Connections - Possible Brute Force Attack |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Rapid POP3 Connections - Possible Brute Force Attack |
| T1110 | T1110 (bridge_table, 0.70) | ET SCAN Rapid POP3S Connections - Possible Brute Force Attack |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN SQLBrute SQL Scan Detected |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Suspicious User-Agent - get-minimal - Possible Vuln Scan |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN WSFuzzer Web Application Fuzzing |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Wapiti Web Server Vulnerability Scan |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Wikto Backend Data Miner Scan |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET SCAN Wikto Scan |
| T1190 | T1190 (declared, 1.00) | ET SCAN ntop-ng Authentication Bypass via Session ID Guessing |
| T1016 | T1016 (ioc_alias, 0.75) | ET TROJAN ATTACKER IRCBot - PRIVMSG Response - ipconfig command output |
| T1105 | T1105 (bridge_table, 0.40) | ET TROJAN HTTP Executable Download from suspicious domain with direct request/fake browser (multiple families) |
| T1105 | T1105 (bridge_table, 0.40) | ET TROJAN Possible Windows executable sent when remote host claims to send html content |
| T1071.001 | T1071.001 (tier2_combined, 0.26) | ET TROJAN Suspicious User-Agent (WindowsNT) With No Separating Space |
| T1016 | T1016 (ioc_alias, 0.75) | ET TROJAN Windows nbtstat -n Microsoft Windows DOS prompt command exit OUTBOUND |
| T1016 | T1016 (ioc_alias, 0.75) | ET TROJAN Windows nbtstat -r Microsoft Windows DOS prompt command exit OUTBOUND |
| T1071.001 | T1071.001 (tier2_combined, 0.31) | ET USER_AGENTS MSF Meterpreter Default User Agent |
| T1203 | T1203 (bridge_table, 0.40) | ET WEB_CLIENT HTA File containing Wscript.Shell Call - Potential CVE-2017-0199 |
| T1190 | T1190 (tier2_combined, 0.36) | ET WEB_SERVER /bin/bash In URI, Possible Shell Command Execution Attempt Within Web Exploit |
| T1190 | T1190 (bridge_table, 0.70) | ET WEB_SERVER CRLF Injection - Newline Characters in URL |
| T1105 | T1105 (bridge_table, 0.40) | ET WEB_SERVER CURL Command Specifying Output in HTTP Headers |
| T1190 | T1190 (tier2_combined, 0.27) | ET WEB_SERVER ColdFusion adminapi access |
| T1190 | T1190 (tier2_combined, 0.26) | ET WEB_SERVER ColdFusion administrator access |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET WEB_SERVER DFind w00tw00t GET-Requests |
| T1595.002 | T1595.002 (bridge_table, 0.70) | ET WEB_SERVER Muieblackcat scanner |
| T1190 | T1190 (declared, 1.00) | ET WEB_SERVER PHP Possible file Remote File Inclusion Attempt |
| T1190 | T1190 (tier2_combined, 0.32) | ET WEB_SERVER PHP SERVER SuperGlobal in URI |
| T1190 | T1190 (declared, 1.00) | ET WEB_SERVER Possible CVE-2014-3120 Elastic Search Remote Code Execution Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SERVER Possible CVE-2015-1427 Elastic Search Sandbox Escape Remote Code Execution Attempt |
| T1190 | T1190 (tier2_combined, 0.35) | ET WEB_SERVER Possible SQL Injection (exec) |
| T1190 | T1190 (tier2_combined, 0.27) | ET WEB_SERVER Possible bash shell piped to dev tcp Inbound to WebServer |
| T1190 | T1190 (tier2_combined, 0.35) | ET WEB_SERVER allow_url_include PHP config option in uri |
| T1190 | T1190 (tier2_combined, 0.34) | ET WEB_SERVER auto_prepend_file PHP config option in uri |
| T1190 | T1190 (tier2_combined, 0.32) | ET WEB_SERVER disable_functions PHP config option in uri |
| T1190 | T1190 (tier2_combined, 0.34) | ET WEB_SERVER safe_mode PHP config option in uri |
| T1190 | T1190 (tier2_combined, 0.32) | ET WEB_SERVER suhosin.simulation PHP config option in uri |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS Achievo debugger.php config_atkroot parameter Remote File Inclusion Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS AjaxPortal ajaxp_backend.php page Parameter SQL Injection |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS AjaxPortal di.php pathtoserverdata Parameter Remote File Inclusion Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS AlstraSoft AskMe que_id Parameter SELECT FROM SQL Injection Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS BaconMap updatelist.php filepath Local File Inclusion Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS Beerwins PHPLinkAdmin edlink.php linkid Parameter SQL Injection |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS Community CMS view.php article_id Parameter SQL Injection |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS CultBooking lang parameter Local File Inclusion Attempt |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS Demium CMS urheber.php name Parameter Local File Inclusion |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS DesktopOnNet don3_requiem.php app_path Parameter Remote File Inclusion |
| T1190 | T1190 (declared, 1.00) | ET WEB_SPECIFIC_APPS DesktopOnNet frontpage.php app_path Parameter Remote File Inclusion |
