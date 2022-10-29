## Generate hysteria's proxy direct connection rules + anti-advertising

Because when the proxy is directly judged by the network segment, the IP returned after dns pollution also belongs to the mainland IP, which will cause the proxy to fail, so add the domain name list and add antiAD easily

The rules are converted to long-term maintenance crash rules: [@Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)

```
#Generate routes.acl + get geoip Country.mmdb>python3 GetRoutes.py
July 07, 2022,Loading...
Block rules: 53337 done.
Direct rules: 66789 done.
Proxy rules: 31924 done.
All rules: 152050
Generate completed!
```