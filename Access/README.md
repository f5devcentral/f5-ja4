# F5 iRules for JA4+ Network Fingerprinting within Access flow

F5 iRules for generating JA4+ fingerprints.  Currently, only JA4, JA4S, JA4T, JA4L, and JA4H fingerprint iRules are provided.  More JA4+ fingerprint iRules *MAY* be added in the future.
The using those fingerprints within Access flow whether to restrict or query ja4db for matching items.

> [!WARNING]
>DISCLAIMER: These iRules are provided as-is with no guarantee of performance or functionality.  Use at your own risk.
>These iRules have been tested on F5 BIGIPs running TMOS versions 16.1 and 17.1.
 

## What is JA4+ Network Fingerprinting?

From the [FoxIO JA4+ Repo](https://github.com/FoxIO-LLC/ja4):
>JA4+ is a suite of network fingerprinting methods that are easy to use and easy to share. These methods are both human >and machine readable to facilitate more effective threat-hunting and analysis. The use-cases for these fingerprints >include scanning for threat actors, malware detection, session hijacking prevention, compliance automation, location >tracking, DDoS detection, grouping of threat actors, reverse shell detection, and many more.

Please read this blog post for more details: [JA4+ Network Fingerprinting](https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637)

To understand how to read JA4+ fingerprints, see [Technical Details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)

## JA4+ Licensing

> [!IMPORTANT]
>**JA4 TLS Client Fingerprinting is licensed under BSD 3-Clause**
>
>_Copyright (c) 2024, FoxIO_
>_All rights reserved.
>JA4 TLS Client Fingerprinting is Open-Source, Licensed under BSD 3-Clause.
>For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4_
>
>
>**All other JA4+ Fingerprints are under the FoxIO License 1.1**
>
>_Copyright (c) 2024, FoxIO, LLC.
>All rights reserved.
>Licensed under FoxIO License 1.1
>For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4_

## How to Use

> Copy the iRules from this folder.
> Add iRule event trigger in your Access Policy.
> In case you try to query external JA4db website, you can utilize HTTP connector to make use of the obtained parameters.
