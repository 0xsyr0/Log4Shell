## Mitigations / Fixes

| URL | Info |
| --- | --- |
| https://www.cisa.gov/uscert/ncas/current-activity/2021/12/22/mitigating-log4shell-and-other-log4j-related-vulnerabilities | CISA - Mitigating Log4Shell and Other Log4j-Related Vulnerabilities |
| https://github.com/apache/logging-log4j2/pull/607 | GitHub - LOG4J2-3198: Log4j2 no longer formats lookups in messages by default #607 |
| https://github.com/apache/logging-log4j2/pull/608#issuecomment-991723301 | log4j2 pull request  |
| https://issues.apache.org/jira/browse/LOG4J2-3198 | apache.org - LOG4J2-3198 |
| https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0 | apache.org - Disable JNDI by default. Fixes LOG4J2-3208, LOG4J2-3211 |
| https://github.com/apache/logging-log4j2/pull/608#issuecomment-993542299 | Restrict LDAP access via JNDI #608 |
| https://issues.apache.org/jira/browse/LOG4J2-3221 | JNDI lookups in layout (not message patterns) enabled in Log4j2 < 2.16.0 |
| https://gist.github.com/jaygooby/3502143639e09bb694e9c0f3c6203949 | fail2ban filter rule for the log4j CVE-2021-44228 exploit |
| https://www.youtube.com/watch?v=w2F67LbEtnk | LiveOverflow - Log4j Vulnerability (Log4Shell) Explained // CVE-2021-44228 |
| https://www.youtube.com/watch?v=iI9Dz3zN4d8 | Log4j Lookups in Depth // Log4Shell CVE-2021-44228 - Part 2 |

<p align="left">
  <img width="800" height="450" src="images/log4j_attack.png">
</p>

Source: https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

<p align="left">
  <img width="800" height="450" src="images/FG-W-NkXIAQlC6b.jpg">
</p>

Source: https://pbs.twimg.com/media/FG-W-NkXIAQlC6b?format=jpg&name=large

#### Patching solr.in.sh

Location:

```
/etc/default/solr.in.sh
```

Add the following line:

```
SOLR_OPTS="$SOLR_OPTS -Dlog4j2.formatMsgNoLookups=true"
```

Restart the Service - done.
