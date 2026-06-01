# Detection Rules

## ICMP Detection

alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)

Purpose:

Detect host discovery attempts through ICMP Echo Requests.

---

## Port Scan Detection

alert tcp any any -> $HOME_NET any (flags:S; msg:"Potential Port Scan"; detection_filter:track by_src,count 10,seconds 5; sid:1000002; rev:2;)

Purpose:

Detect TCP SYN reconnaissance activity while reducing false positives.

---

## HTTP SQL Injection Detection

alert tcp any any -> $HOME_NET 80 (msg:"Possible SQL Injection"; content:"union"; nocase; sid:1000003; rev:1;)

Purpose:

Detect HTTP requests containing UNION-based SQL Injection patterns.
