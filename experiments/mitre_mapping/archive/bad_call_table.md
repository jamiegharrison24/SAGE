| signature | GT (stage -> ids) | 1_attackbert_full | 2_attackbert_filtered | 3_minilm_full | 4_minilm_filtered | 5_knn_attackbert | 6_knn_minilm | 7_smet |
|---|---|---|---|---|---|---|---|---|
| ET WEB_SERVER /etc/shadow Detected in URI | DATA_EXFILTRATION -> T1041 | T1505.004 | T1036.012 | T1003.008 | T1056.003 | TA0011 | T1041 | T1568 |
| ET ATTACK_RESPONSE Net User Command Response | COMMAND_AND_CONTROL -> TA0011 | T1557.001 | T1557.001 | T1059.008 | T1059.008 | T1041 | T1041 | T1033 |
| ET CHAT Skype VOIP Checking Version (Startup) | NON_MALICIOUS -> (none) | T1123 | T1205.001 | T1552.008 | T1016.001 | T1046 | T1592 | T1082 |
| SERVER-MYSQL MySQL/MariaDB Server geometry query object integer overflow attempt | END_POINT_DOS -> T1499 | T1027.001 | T1030 | T1030 | T1030 | T1499 | T1203 | T1030 |
| ET WEB_SERVER MYSQL SELECT CONCAT SQL Injection Attempt | DATA_MANIPULATION -> T1565 | T1505.003 | T1505.003 | T1213.006 | T1213.006 | T1565 | T1565 | T1190 |
| FILE-FLASH Adobe Flash Player use after free attempt | PRIV_ESC -> TA0004 | T1027.006 | T1027.006 | T1204.002 | T1566.001 | TA0004 | TA0004 | T1036 |
| ET WEB_SPECIFIC_APPS Noname Media Photo Galerie Standard SQL Injection Attempt -- view.php id SELECT | ARBITRARY_CODE_EXE -> T1203 | T1595.003 | T1595.003 | T1204.003 | T1204.003 | T1203 | T1203 | T1083 |
| ET CURRENT_EVENTS Malformed HeartBeat Response | VULN_DISC -> T1595.002 | T1685.004 | T1205.002 | T1685.005 | T1546 | TA0004 | TA0004 | T1497 |
| ET CURRENT_EVENTS Malformed HeartBeat Request | VULN_DISC -> T1595.002 | T1685.004 | T1205.002 | T1685.005 | T1546 | TA0004 | TA0004 | T1497 |
| ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT | DATA_MANIPULATION -> T1565 | T1505.003 | T1505.003 | T1110.003 | T1056.003 | T1565 | T1565 | T1190 |
| ET CURRENT_EVENTS Possible OpenSSL HeartBleed Large HeartBeat Response (Server Init Vuln Client) | PRIV_ESC -> TA0004 | T1499.001 | T1499.001 | T1190 | T1190 | TA0004 | TA0004 | T1497 |
| ET CURRENT_EVENTS Possible OpenSSL HeartBleed Large HeartBeat Response (Client Init Vuln Server) | PRIV_ESC -> TA0004 | T1499.001 | T1499.001 | T1190 | T1190 | TA0004 | TA0004 | T1497 |
| ET WEB_SPECIFIC_APPS PHPOF DB_AdoDB.Class.PHP PHPOF_INCLUDE_PATH parameter Remote File Inclusion | DATA_DELIVERY -> T1105 | T1218.001 | T1218.001 | T1218.008 | T1218.008 | T1105 | T1105 | T1505 |
| ET WEB_SERVER PHP Easteregg Information-Disclosure (zend-logo) | INFO_DISC -> T1592;T1590 | T1027.012 | T1027.012 | T1036.002 | T1027.003 | T1592 | T1592 | T1082 |
| GPL CHAT Google Talk Startup | NON_MALICIOUS -> (none) | T1213.005 | T1071.005 | T1213.005 | T1552.006 | T1592 | T1592 | T1102 |
