#!/bin/bash
set="blocked_ips"
limit=100
sudo ipset destroy $set &>/dev/null
sudo ipset create $set hash:ip
sudo iptables -D INPUT -m set --match-set $set src -j DROP &>/dev/null
sudo iptables -I INPUT -m set --match-set $set src -j DROP
while true; do
  ss -tn state established | awk '{print $5}' | cut -d':' -f1 | sort | uniq -c | sort -nr | while read count ip; do
    [[ $count -ge $limit && $ip != "address" ]] && ! sudo ipset test $set $ip &>/dev/null && sudo ipset add $set $ip
  done
  sleep 5
done

