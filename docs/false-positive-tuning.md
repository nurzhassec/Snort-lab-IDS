# False Positive Tuning

## Problem

The initial port scan rule generated an alert for every TCP SYN packet.

Original Rule:

alert tcp any any -> $HOME_NET any (flags:S; msg:"Possible Port Scan"; sid:1000002; rev:1;)

This behavior produced false positives because normal TCP connections also begin with a SYN packet.

Examples:

* Web browsing
* SSH sessions
* Application connections

---

## Tuning Process

A detection filter was introduced:

alert tcp any any -> $HOME_NET any (flags:S; msg:"Potential Port Scan"; detection_filter:track by_src,count 10,seconds 5; sid:1000002; rev:2;)

---

## Logic

The updated rule requires:

* At least 10 SYN packets
* From the same source host
* Within a 5-second interval

before generating an alert.

---

## Result

Normal web traffic no longer triggered alerts.

Nmap SYN scans continued to generate alerts successfully.

This significantly reduced false positives and improved detection quality.
