# Network datasets

A dataset is a set of packet capture files that can be analyzed using the network packet analyzers. Many network datasets are available on the Internet.

In 2019, the authors of the article "A survey of network-based intrusion detection data sets" published in the journal "Computers & Security," researched the network-based datasets. They described available packet-based and flow-based datasets for IDS in the mentioned article. The discussed datasets include AWID (2016), Booters (2015), Botnet (2014), CIC DoS (2017), CICIDS 2017 (2018), CIDDS-001 (2017), CIDDS-002 (2017), CDX (2009), CTU-13 (2014), DARPA (2000), DDoS 2016 (2016), IRSC (2015), ISCX 2012 (2012), ISOT (2011), KDD CUP 99 (2018), Kent 2016 (2015), Kyoto 2006+ (2011), LBNL (2005), NDSec-1 (2017), NGIDS-DS (2017), NSL-KDD (2009), PU-IDS (2015), PUF (2018), SANTA (2014), SSENET-2011 (2011), SSENET-2014 (2014), SSHCure (2014), TRAbID (2017), TUIDS (2012), Twente (2009), UGR’16 (2018), UNIBS (2009), Unified Host and Network (2017), UNSW-NB15 (2015). The article is available under [DOI 10.1016/j.cose.2019.06.005](https://doi.org/10.1016/j.cose.2019.06.005).

 There are also some websites that contain set of publicky available PCAP files such as  [NETRESEC publicly available PCAP files](https://www.netresec.com/?page=PcapFiles). The NETRESEC provides a list of several publicly available datasets separated into categories: Cyber Defence Exercises (CDX), Malware Traffic, Network Forensics, SCADA/ICS Network Captures, Capture the Flag Competitions (CTF), Packet Injection Attacks/Man-on-the-Side Attacks, Uncategorized PCAP Repositories, and Single PCAP files.

The following sections provide a detailed description of some datasets.

## [Canadian Institute for Cybersecurity datasets](https://www.unb.ca/cic/datasets/)

The "Canadian Institute for Cybersecurity" created datasets that are focused of several aspects of cyersecurity. The currently available datasets include Android malware, DoS, VPN, Tor, IPS/IDS, and DNS over HTTP traffic. Some datasets are described in the following sections.

### [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html)

The dataset *DDoS2019* is a dataset of "Canadian Institute for Cyersecurity" that contains benign and most up-to-data DDoS attacks. The dataset contains realistic background traffic. There was built the abstract behaviour of 25 users based on the HTTP, HTTPS, FTP, SSH, and email protocols.

The dataset contains captured data from 2 days. The first day, the training day, took place on 3.11.2018, started at 09:40 and ended at 17:35 local time (converted into UTC time format: from 12:40 UTC to 20:35 UTC). The second day, the testing day, took place on 1.12.2018, started at 10:30 and ended at 17:15 local time (converted into UTC time format: from 13:30 UTC to 20:15 UTC). The original dataset description uses wrong dates in the research paper (followed by switched naming of the first and the second day) - ,they use the first day as the January 12th and the second day as the March 11th. The information used in this document is based on the PCAP files and CSV files of this dataset, not the research paper. Therefore they differ from the original dataset's descriptions. This dataset includes PortScan, NetBIOS, LDAP, MSSQL, UDP, UDP-Lag, SYN, NTP, DNS, SNMP, SSDP, WebDDoS, and TFTP attacks.

The following table contains the victim network information. The attacker network consists of the third party company.

| | |
--- | --- |
**Firewall** | 205.174.165.81 (Fortinet)    
**Victim** |  192.168.50.4 (First day), 192.168.50.1 (Second day) (Web server Ubuntu 16.04), 192.168.50.9 (First day), 192.168.50.8 (Second day) (Win 7 Pro), 192.168.50.6 (First day), 192.168.50.5 (Second day) (Win Vista), 192.168.50.7 (First day), 192.168.50.6 (Second day) (Win 8.1), 192.168.50.8 (First day), 192.168.50.7 (Second day) (Win 10 Pro 32)

The original dataset PCAPs are split into multiple PCAP files. The first day contains 145 PCAPs, the second day contains 818 PCAPs. The individual capture days of the dataset are discussed in the following sections. Firstly, the essential time frames of some individual PCAPs of that day are described (timestamps of the start and end of attacks). Secondly, the annotation of the whole day is provided. The time is in the UTC format. The description of the attacks are based on the research paper "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy"

* Iman Sharafaldin, Arash Habibi Lashkari, Saqib Hakak, and Ali A. Ghorbani, "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy", IEEE 53rd International Carnahan Conference on Security Technology, Chennai, India, 2019

**First day - training day**

The following table dispalys important time frames of some PCAP files of the first day 3.11.2018.

PCAP filename | Time range (UTC) 
--- | --- |
SAT-03-11-2018\_000	|	12:18:16.583626 -	13:01:48.920573 
SAT-03-11-2018\_011	|	13:09:00.565557 -	13:21:56.124692 
SAT-03-11-2018\_068	|	13:29:52.072724 -	13:34:11.268896 
SAT-03-11-2018\_106	|	13:42:57.176611 -	13:54:11.631481 
SAT-03-11-2018\_136	|	14:01:43.652741 -	14:14:54.297925 
SAT-03-11-2018\_137	|	14:14:54.298079 -	14:30:25.830426 
SAT-03-11-2018\_145	|	17:51:18.675623 -	20:36:56.349321

* **Number of packets:** 61 407 883
* **Timeline:** 2018-11-03 12:18:16.583626 UTC - 2018-11-03 20:36:56.349321 UTC
* **Involved hosts:** 172.16.0.5, 192.168.50.4, 192.168.50.6, 192.168.50.7, 192.168.50.8, 192.168.50.9
* **Protocols:** 3Com XNS, 3GPP2 A11, 802.11, A21, ADP, AH, ALC, ALLJOYN-ARDP, ALLJOYN-NS, AMS, AMT, ANSI C12.22, AODV, ARP, ASAP, ASTERIX, ATH, AX4000, AYIYA, Auto-RP, BACnet-APDU, BAT\_BATMAN, BAT\_GW, BAT\_VIS, BFD Control, BJNP, BOOTP, BROWSER, BVLC, Bundle, CAPWAP-Control, CAPWAP-Data, CDP, CLDAP, CLNP, CN/IP, CUPS, CoAP, DAYTIME, DB-LSP-DISC, DCC, DCERPC, DCP-AF, DCP-PFT, DHCP, DHCPv6, DIS, DMP, DNP, DNS, DPNET, DPP, DSR, DTLS, DTP, EAP, EAPOL, ECAT, ECATF, ECHO, ECMP, EGD, EIGRP, ENIP, ENRP, ESP, Elasticsearch, GPRS-NS, GSM SIM, GSMTAP, GTP, Geneve, H.225.0, H.248, HART\_IP, HCrt, HPEXT, HTTP, HTTP/XML, HiQnet, IAPP, IAX2, ICMP, ICMPv6, ICP, IEEE 802.15.4, IGMPv3, IO-RAW, IP, IPVS, IPX, IPv4, IPv6, ISAKMP, ISO, KDP, KINK, KNET, KPASSWD, KRB4, KRB5, L2TP, L2TPv3, LBT-RU, LDP, LISP, LLC, LLDP, LLMNR, LMP, LTP Segment, LWAPP, MANOLITO, MDNS, MEMCACHE, MIH, MIPv6, MNDP, MPLS, MSMMS, MSproxy, MiNT, MobileIP, Modbus/UDP, NAT-PMP, NBDS, NBNS, NCP, NHRP, NTP, NXP 802.15.4 SNIFFER, Nano, OCSP, OLSR v1, OSPF, OpenVPN, PCP v1, PCP v2, PFCP, PKTC, PNIO, POWERLINK/UDP, PTPv2, Pathport, Portmap, QUAKE, QUAKE2, QUAKE3, QUAKEWORLD, RADIUS, RDT, RIP, RIPng, RIPv1, RIPv2, RRoCE, RSIP, RSVP, RTCP, RTPproxy, RakNet, SABP, SAP, SAP/SDP, SCTP, SCoP, SEBEK, SIP, SNA, SNMP, SRVLOC, SSDP, SSH, SSHv2, SSL, SSLv2, STP, STUN, SliMP3, Syslog, TAPA, TC-NV, TCP, TETRA, TFTP, TIME, TIPC, TLSv1, TLSv1.2, TLSv1.3, TPCP, TPKT, TS2, TSP, TZSP, UAUDP, UDP, UDP/MIKEY, ULP, UNKNOWN, VITA 49, Vines IP, Vuze-DHT, VxLAN, WHO, WLCCP, WSP, WTLS+WSP, WTLS+WTP+WSP, WTP+WSP, X.25, XTACACS, XYPLEX, collectd, eDonkey, lw\_res, openSAFETY over UDP, packetbb 
* **Attacks:** PortMap (12:43 - 12:51), NetBIOS (13:01 - 13:09), LDAP (13:21 - 13:30), MSSQL (13:33 - 13:43), UDP (13:52 - 14:04), UDP-Lag (14:14 - 14:24), SYN (14:28 - 20:35)

**Second day - testing day**

The following table dispalys important time frames of some PCAP files of the second day 1.12.2018.

PCAP filename | Time range (UTC) 
--- | --- |
SAT-01-12-2018\_0	|		13:17:10.711517		-		14:36:06.133219 
SAT-01-12-2018\_027	|		14:36:59.617966		-		14:37:02.505099 
SAT-01-12-2018\_0188	|		14:44:33.210758		-		14:46:30.026952 
SAT-01-12-2018\_0190	|		14:48:26.225518		-		14:51:39.813446 
SAT-01-12-2018\_0194	|		14:57:43.395236		-		15:00:26.604875 
SAT-01-12-2018\_0195	|		15:00:26.604876		-		15:03:06.989875 
SAT-01-12-2018\_0305	|		15:11:56.643849		-		15:12:00.253348 
SAT-01-12-2018\_0324	|		15:12:59.381993		-		15:13:02.627201 
SAT-01-12-2018\_0381	|		15:22:58.494906		-		15:23:07.641045 
SAT-01-12-2018\_0387	|		15:23:53.444988		-		15:24:02.172861  
SAT-01-12-2018\_0407	|		15:26:51.191475		-		15:27:00.259048 
SAT-01-12-2018\_0414	|		15:27:56.123811		-		15:28:05.086642 
SAT-01-12-2018\_0443	|		15:32:32.915441		-		15:37:20.477580 
SAT-01-12-2018\_0446	|		15:37:56.549979		-		15:38:15.028105 
SAT-01-12-2018\_0467	|		15:44:53.078912		-		15:45:12.275065 
SAT-01-12-2018\_0470	|		15:45:48.874827		-		15:46:07.180524 
SAT-01-12-2018\_0486	|		16:00:13.902782		-		16:13:19.200714 
SAT-01-12-2018\_0501	|		16:14:53.513548		-		16:15:00.789394 
SAT-01-12-2018\_0510	|		16:15:58.289530		-		16:16:05.415448 
SAT-01-12-2018\_0526	|		16:17:53.645195		-		16:18:00.844202 
SAT-01-12-2018\_0535	|		16:18:57.740588		-		16:19:04.830961 
SAT-01-12-2018\_0577	|		16:28:47.412567		-		16:29:26.085243 
SAT-01-12-2018\_0578	|		16:29:26.085244		-		16:30:14.334464 
SAT-01-12-2018\_0584	|		16:33:24.858564		-		16:34:12.351220 
SAT-01-12-2018\_0586	|		16:34:45.229199		-		16:35:19.639364 
SAT-01-12-2018\_0589	|		16:35:55.110452		-		16:36:11.265191 
SAT-01-12-2018\_0817	|		18:02:49.179574		-		20:59:05.159078 
SAT-01-12-2018\_0818	|		20:59:05.159081		-		21:16:39.140675 

* **Number of packets:** 250 783 287
* **Timeline:** 2018-12-01 13:17:10.711517 UTC - 2018-12-01 21:16:39.140675 UTC
* **Involved hosts:** 192.168.0.1, 192.168.0.5, 192.168.0.6, 192.168.0.7, 192.168.0.8
* **Protocols:** 3Com XNS, 3GPP2 A11, 802.11, A21, ADP, ALC, ALC/XML, ALLJOYN, ALLJOYN-ARDP, ALLJOYN-NS, AMS, AMT, ANSI C12.22, AODV, ARP, ASAP, ASF, ASTERIX, ATH, AX4000, AYIYA, Armagetronad, Auto-RP, BACnet-APDU, BAT\_BATMAN, BAT\_GW, BAT\_VIS, BFD Control, BJNP, BOOTP, BROWSER, BSSGP, BVLC, Bundle, CAPWAP-Control, CAPWAP-Data, CAT-TP, CDP, CLDAP, CLNP, CN/IP, CUPS, CoAP, DAYTIME, DB-LSP-DISC, DCC, DCERPC, DCP-AF, DCP-PFT, DHCP, DHCPv6, DIS, DMP, DNP, DNS, DPNET, DPP, DSPv2 , DSR, DTLS, DTP, EAP, EAPOL, EAPOL-MKA, ECAT, ECATF, ECHO, ECMP, EGD, EIGRP, ENIP, ENRP, ESP, Elasticsearch, Ethernet, FF, GPRS-LLC, GPRS-NS, GSM SIM, GSMTAP, GTP, GTPv2, Geneve, H.225.0, H.248, HART\_IP, HCrt, HPEXT, HTTP, HTTP/XML, HiQnet, IAPP, IAX2, ICMP, ICMPv6, ICP, IEEE 802.15.4, IO-RAW, IP, IPMI, IPVS, IPX, IPv4, IPv6, ISAKMP, ISO, KDP, KINK, KNET, KPASSWD, KRB4, KRB5, L2TP, L2TPv3, LDP, LISP, LLC, LLDP, LLMNR, LMP, LTP Segment, LWAPP, MAC-Telnet, MANOLITO, MDNS, MEMCACHE, MIH, MIPv6, MNDP, MPLS, MSMMS, MSproxy, MiNT, MobileIP, Modbus/UDP, NAT-PMP, NBDS, NBNS, NCP, NEMO, NHRP, NTP, NXP 802.15.4 SNIFFER, Nano, NetBIOS, OCSP, OLSR v1, OSCORE, OSPF, OpenVPN, PCP v1, PCP v2, PFCP, PKTC, PN-PTCP, PNIO, POWERLINK/UDP, PTPv2, Pathport, QUAKE, QUAKE2, QUAKE3, QUAKEWORLD, RADIUS, RDT, RIP, RIPng, RIPv1, RIPv2, RMCP, RRoCE, RSIP, RSVP, RTCP, RTPproxy, RX, RakNet, SABP, SAP, SAP/SDP, SCTP, SCoP, SEBEK, SIP, SNA, SNMP, SPX, SRVLOC, SSDP, SSH, SSHv2, SSL, STP, SliMP3, Syslog, TACACS, TAPA, TC-NV, TCP, TETRA, TFTP, TIME, TIPC, TLSv1, TLSv1.2, TLSv1.3, TPCP, TPKT, TS2, TSP, TZSP, Thread, UAUDP, UDP, UDP/MIKEY, ULP, UNKNOWN, VITA 49, Vines IP, Vuze-DHT, VxLAN, WHO, WLCCP, WSP, WTLS+WSP, WTLS+WTP+WSP, WTP+WSP, X.25, XTACACS, XYPLEX, ZigBee IP, collectd, eDonkey, lw\_res, openSAFETY over UDP, openSAFETY/UDP, packetbb
* **Attacks:** NTP (13:35 - 13:45), DNS (13:52 - 14:05), LDAP (14:22 - 14:32), MSSQL (14:36 - 14:45), NetBIOS (14:50 - 15:00), SNMP (15:12 - 15:23), SSDP (15:27 - 15:37), UDP (15:45 - 16:09), UDP-Lag (16:11 - 16:15), WebDDoS (16:18 - 16:29), SYN (16:29 - 16:34), TFTP (16:35 - 20:15)

### [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)

The dataset "IDS 2017" contains benign and the most up-to-date common attacks. It reflects a realistic background traffic. This dataset contains the built abstract behaviour of 25 users based on the HTTP, HTTPS, FTP, SSH, and email protocols.

The captured data are spitted into 5 PCAP files according to the day of the week they were captured. The data are captured from 3.7.2017 12:00 PM UTC (Monday) to 7.7.2017 8:00 PM UTC (Friday), in local time from Monday 9:00 AM to Friday 5:00 PM. This dataset include Brute Force FTP, Brute Force SSH, DoS, Heartbleed, Web Attack, Infiltration, Botnet and DDoS attacks.

The following table contains the network information of the dataset, including firewall, DNS server, attackers network and victim network. 

| | |
--- | --- |
**Firewall** | 205.174.165.80, 172.16.0.1   
**DC and DNS Server** |  192.168.10.3 (Win server 2016)
**Attackers** | 205.174.165.69, 205.174.165.70, 205.174.165.71 (Win)
**Victim** | 192.168.10.50, 205.174.165.68 (Web server Ubuntu 16), 192.168.10.51, 205.174.165.66 (Ubuntu server 12), 192.168.10.19 (Ubuntu 14.4, 32B), 192.168.10.17 (Ubuntu 14.4, 64B), 192.168.10.16 (Ubuntu 16.4, 32B), 192.168.10.12 (Ubuntu 16.4, 64B), 192.168.10.9 (Win 7 Pro, 64B), 192.168.10.5 (Win 8.1, 64B), 192.168.10.8 (Win Vista, 64B), 192.168.10.14 (Win 10, pro 32B), 192.168.10.15 (Win 10, 64B), 192.168.10.25 (MAC)

The following description of the individual days is based on the dataset description and the research paper "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization".

* Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization”, 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018

Timeline is displayed in UTC (Coordinated Universal Time) format. Involved hosts displayed in each day include only hosts from network information (attackers, victim, firewall).

**Monday**
 
* **Number of packets:** 11 709 971
* **Timeline:** 2017-07-03 11:55:58.598308 AM - 2017-07-03 8:01:34.472889 PM
* **Involved hosts:** 172.16.0.1, 192.168.10.5, 192.168.10.8, 192.168.10.9, 192.168.10.12, 192.168.10.14, 192.168.10.15, 192.168.10.16, 192.168.10.17, 192.168.10.19, 192.168.10.25, 192.168.10.50, 192.168.10.51, 
* **Protocols:** ARP, BJNP, BROWSER, CDP, CLDAP, DCERPC, DHCPv6, DNS, DRSUAPI, EPM, Elasticsearch, FTP, FTP-DATA, GQUIC, HTTP, HTTP/XML, ICMP, ICMPv6, IGMPv2, IGMPv3, IPv4, KRB5, LANMAN, LDAP, LLDP, LLMNR, LSARPC, MDNS, MP4, NBNS, NBSS, NTP, OCSP, OpcUa, PKIX-CRL, RPC\_NETLOGON, SAMR, SMB, SMB2, SRVSVC, SSDP, SSH, SSHv2, SSL, SSLv2, SSLv3, STUN, TCP, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3, UDP, WebSocket
* **Attacks:** None
 

**Tuesday**
 
* **Number of packets:** 11 551 954
* **Timeline:** 2017-07-04 11:53:32.364079 AM - 2017-07-04 8:00:31.076755 PM
* **Involved hosts:**  172.16.0.1, 172.16.0.10, 192.168.10.50, 205.174.165.68, 205.174.165.73, 205.174.165.80
* **Protocols:** ARP, BJNP, BROWSER, CDP, CLDAP, DCERPC, DHCPv6, DNS, DRSUAPI, EPM, FTP, FTP-DATA, HTTP, HTTP/XML, ICMP, ICMPv6, IGMPv2, IGMPv3, IPv4, KRB5, LANMAN, LDAP, LLDP, LLMNR, LSARPC, MDNS, MP4, NBNS, NBSS, NTP, OCSP, PKIX-CRL, RPC\_NETLOGON, SAMR, SMB, SMB2, SRVSVC, SSDP, SSH, SSHv2, SSL, SSLv2, SSLv3, STUN, TCP, TLSv1, TLSv1.1, TLSv1.2, UDP
* **Attacks:** Brute Force, FTP-Patator (12:20 PM - 1:20 PM), SSH-Patator (5:00 PM - 6:00 PM)
 

**Wednesday**
 
* **Number of packets:** 13 788 878
* **Timeline:** 2017-07-05 11:42:42.084372 AM - 2017-07-05 8:10:19.780725 PM
* **Involved hosts:** 172.16.0.1, 172.16.0.10, 172.16.0.11, 192.168.10.50, 192.168.10.51, 205.174.165.66, 205.174.165.68, 205.174.165.73, 205.174.165.80
* **Protocols:** ARP, BJNP, BROWSER, CDP, CLDAP, DCERPC, DHCPv6, DNS, DRSUAPI, DTLS, DTLSv1.2, EPM, FTP, FTP-DATA, HTTP, HTTP/XML, ICMP, ICMPv6, IGMPv2, IGMPv3, IPv4, KRB5, LANMAN, LDAP, LLDP, LLMNR, LSARPC, MDNS, MP4, MPEG, NBNS, NBSS, NTP, OCSP, RPC\_NETLOGON, SAMR, SMB, SMB2, SRVSVC, SSDP, SSH, SSHv2, SSL, SSLv2, SSLv3, STUN, TCP, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3, UDP, WebSocket
* **Attacks:** DoS slowloris (12:47 PM - 1:10 PM), DoS Slowhttptest (1:14 PM - 1:35 PM), DoS Hulk (1:43 PM - 2:00 PM), DoS GoldenEye (2:10 PM - 2:23 PM), Heartbleed Port 444 (6:12 PM - 6:32 PM)
 

**Thursday**
 
* **Number of packets:** 9 322 025
* **Timeline:** 2017-07-06 11:58:58.492265 AM - 2017-07-06 8:04:44.364012 PM
* **Involved hosts:** 172.16.0.1, 172.16.0.10, 192.168.10.8, 192.168.10.25, 192.168.10.50, 205.174.165.68, 205.174.165.73, 205.174.165.80
* **Protocols:** ARP, BJNP, BROWSER, CDP, CLDAP, DCERPC, DHCPv6, DNS, DRSUAPI, EPM, FTP, FTP-DATA, HTTP, HTTP/XML, ICMP, ICMPv6, IGMPv2, IGMPv3, IPv4, KRB5, LANMAN, LDAP, LLDP, LLMNR, LSARPC, MDNS, MP4, MPEG PES, NBNS, NBSS, NTP, OCSP, PKIX-CRL, RPC\_NETLOGON, SMB, SMB2, SRVSVC, SSDP, SSH, SSHv2, SSL, SSLv2, SSLv3, STUN, TC, TCP, TLSv1, TLSv1.1, TLSv1.2, UDP
* **Attacks:** Web attacks -- Brute Force (12:20 PM - 1:00 PM), XSS (1:15 PM - 1:35 PM), Sql Injection (1:40 PM - 1:42 PM), Infiltration attacks - Dropbox download Win Vista (5:19 PM, and 5:20 PM - 5:21 PM, and 5:33 PM - 5:35 PM, 6:04 PM - 6:45 PM), Cool disk MAC (5:53 PM - 6:00 PM)
 

**Friday**
 
* **Number of packets:** 9 997 874
* **Timeline:** 2017-07-07 11:59:39.599128 AM - 2017-07-07 8:02:41.169108 PM
* **Involved hosts:** 172.16.0.1, 192.168.10.5, 192.168.10.8, 192.168.10.9, 192.168.10.14, 192.168.10.15, 192.168.10.50, 205.174.165.68, 205.174.165.69, 205.174.165.70, 205.174.165.71,  205.174.165.73, 205.174.165.80
* **Protocols:** ARP, BJNP, BROWSER, CDP, CLDAP, DCERPC, DHCPv6, DNS, DRSUAPI, EPM, FTP, FTP-DATA, H1, HTTP, HTTP/XML, ICMP, ICMPv6, IGMPv1, IGMPv2, IGMPv3, IPv4, KRB5, LANMAN, LDAP, LLDP, LLMNR, LSARPC, MDNS, MPEG PES, NBNS, NBSS, NTP, OCSP, OMAPI, PKIX-CRL, RPC\_NETLOGON, SAMR, SCTP, SMB, SMB2, SRVSVC, SSDP, SSH, SSHv2, SSL, SSLv2, SSLv3, STUN, TCP, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3, UDP
* **Attacks:** Botnet ARES (1:02 PM - 2:02 PM), DDoS LOIT (6:56 PM - 7:16 PM), Port Scan (sS, sT, sF, sX, sN, sP, sV, sU, sO, sA, sW, sR, sL and B)
 

## [Nitroba University Harassment Scenario](https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario)

A "Nitroba University Harassment Scenario" is a hypothetical network forensic scenario created by the "Digital Corpora". The scenario consists of the slides that introduce the problem (PDF, PPT or TXT file), screenshots in PNG format as a part of the problem introduction, and a PCAP file of the captured traffic. There is also available password-protected solution of this scenario.

The background of this case is the harassment of the teacher Lily Tuckrige (lilytuckrige@yahoo.com). She thinks that harassing emails are from one of her students (Amy Smith, Burt Greedom, Tuck Gorge, Ava Book, Johnny Coach, Jeremy Ledvkin, Nancy Colburne, Tamara Perkins, Esther Pringle, Asar Misrad, Jenny Kan). The provided information contains screenshots of the harrasing emails (including the email header), the IP from the email (140.247.62.34) that points into *34.62.247.140.in-addr.arpa domain name pointer G24.student.nitroba.org*, this Nitroba dorm room has wifi without password and three women live here (Alice,  Barbara, Candice). The PCAP capture file contains traffic from the packet sniffer placed on the ethernet port. The goal of this scenario is to determine who is responsible for the harassing emails.

* **Number of packets:** 94 410
* **Timeline:** 
    2008-07-22 01:51:07.095278 UTC - 2008-07-22 06:13:47.046029 UTC 
* **Involved hosts:** 192.168.15.4 (attacker), 140.247.62.34 (attacker), 209.73.187.220 (answers.yahoo.com), 74.125.19.104 (www.google.com), 74.125.19.17 (mail.google.com), 69.80.225.91 (www.sendanonymousemail.net), 65.54.186.77 (login.live.com)
* **Protocols:** YMSG, XMPP/XML, UDPENCAP, UDP, TLSv1, TCP, SSLv3, SSLv2, SSL, SSDP, SIP/SDP, SIP, RTP, RTCP, RIPv2, RIPv1, OCSP, NTP, Messenger, MSNMS, LLC, ISAKMP, IGMPv3, IGMPv2, ICMP, HTTP/XML, HTTP, ESP, DNS, DCERPC, ARP

**Case theory - report of the scenario**

Gmail user jcoachj@gmail.com logged into the gmail on 22.7.2008 06:01:02 UTC on the computer with IP 192.168.15.4 with operating system Apple iOS. Using the same web browser, the user searched for "how to annoy people", "sending anonymous mail" and "I want to harass my teacher" on Google approximately about 05:57 on 22.7.2008. Then the user search for "can I go to jail for harassing my teacher" on 22.7.2008 05:58.

After that, at 05:59, there was a login on mail.live.com. At 06:00, the mail.google.com was visited by the user jcoachj@gmail.com (used *gmailchat* cookie) witch proves that this user used this computer (IP: 192.168.15.4). 

At 06:01, the user visited www.sentanonymousemail.net. Then the user sent two emails using anonymous mail delivery. The first one was sent using www.sentanonymousemail.net on 22.7.2008 06:02:57 UTC. The second one was sent using willselfdestruct.com on 22.7.2008 06:04:24 UTC. After that, the user searched for "where do the cool kids go to play" on Google and visited youtube.com. These actions prove that the Johnny Coach is the person who harassed his teacher Lily Tuckrige. 

On 22.7.2008 06:09:59 UTC, the user amy789smith authenticated with Yahoo, but there was used different web browser, and therefore Amy Smith did not send the harassment emails.

## [NETRESEC Packet Injection Attacks](https://www.netresec.com/?page=Blog&month=2016-03&post=Packet-Injection-Attacks-in-the-Wild)

Erik Hjelmvik, in his article 
"Packet Injection Attacks in the Wild," focused on the packet injection attacks that have been running for several months and that was still active in 2016. They attempted to recreate these packet injections and provided PCAP files.

The first attack that they recreated was against the *www.02995.com*. It belongs to the "hao" group of the original research "Website-Targeted False Content Injection by Network Operators". The second attack was against the *id1.cn*. This injection attack was based on the BroCon 2015.

The details of the performed attacks are described in the following sections, including annotations of the provided PCAP files.

### Packet injection attack against *www.02995.com*
After visiting the website *www.02995.com*, the two responses are generated with the same sequence number (3820080905):
 
1. "302 Found" - redirect to *http://www.hao123.com/?tn=93803173_s_hao_pg* 
    injected packet; uses only LF as line feed in the HTTP header,
2. "302 Moved Temporarily" - redirect to *http://hao.360.cn/?src=lm\&ls=n4a2f6f3a91* 
    real webserver response; uses the standard CR-LF line breaks in the HTTP response

The user is redirected to the *http://www.hao123.com/*, because the injected response arrived before the real webserver response.

**Annotation of the PCAP file**
 
* **Number of packets:** 202
* **Timeline:**
    2016-03-01 08:03:47.560150 UTC - 2016-03-01 08:04:10.149843 UTC 
* **Involved hosts:** 103.235.46.234 (www.hao123.com), 122.225.98.197 (www.02995.com), 192.168.1.254 (Windows)
* **Protocols:** HTTP, TCP
 

### Packet injection attack against *id1.cn*
After visiting the website *id1.cn*, three responses are returned:
 
1. "200 OK" - redirect to *http://id1.cn/rd.s/Btc5n4unOP4UrIfE?url=http://id1.cn/*, real webserver response, client proceeds this website (this is the first response) and gets two injected responses and one real website response:
     
    * "403 Forbidden" - redirect to *http://batit.aliyun.com/alww.html*
    * "403 Forbidden" - redirect to *http://batit.aliyun.com/alww.html*
    * "200 OK" - redirect to *http://id1.cn/*, real website response
     
2. "403 Forbidden" - redirect to *http://batit.aliyun.com/alww.html*, injected response,
3. "403 Forbidden" - redirect to *http://batit.aliyun.com/alww.html*, injected response.
 

**Annotation of the PCAP file**
 
* **Number of packets:** 155
* **Timeline:** 
    2016-03-01 08:00:19.058801 UTC - 2016-03-01 08:00:28.839398 UTC 
* **Involved hosts:** 42.96.141.35 (id1.cn), 42.120.158.95 (batit.aliyun.com), 192.168.1.254 (Windows)
* **Protocols:** HTTP, TCP
 

## [ICS Cybersecurity - DoS Attacks against SCADA-based systems](https://github.com/tjcruz-dei/ICS_PCAPS/releases/tag/MODBUSTCP%231)

The ICS Cybersecurity PCAP repository is a suite of PCAP captures that includes the "modbus TCP SCADA" dataset  created by a team from the University of Coimbra (Portugal), as a part of the ATENA H2020 project. This dataset was generated for the article "Denial of Service Attacks: Detecting the frailties of machine learning algorithms in the Classification Process" using MODBUS/TCP equipment in the SCADA system.

The captured data is organized into three folders containing sub-folders based on the type of the attack, including ARP-based, Main-in-the-Middle attack, Modbus query flooding, ICMP flooding, and TCP SYN flooding. In addition, a nominal state with no attack is included. There is a naming convention for the PCAP files `<capture interface>dump-<attack>-<attack subtype>-<attack duration>-<capture duration>`. Each attack starts 5 minutes after the first captured packet. The PCAP files with 12 hour capture duration are excluded, this project includes only 0.5 h, 1 h, 6 h, and 12 h captures. The brief overall description for each category is provided in the following sections. The time is in the UTC format, and flooding attacks hosts do not contain all involved host IP addresses (since many third-party IPs are involved in the DDoS attacks).

The following table displays the network information about this dataset.

| | |
--- | --- |
**Attackers** | 172.27.224.50, 172.27.224.80  
**Victim** |  172.27.224.11, 172.27.224.70, 172.27.224.250, 172.27.224.251

**Nominal state**

* **Number of PCAPs:** 3
* **Total number of packets:** 535 422
* **Total timeline:** 2018-08-23 17:40:48.376131 UTC - 2018-09-09 00:14:03.946853 UTC
* **Total involved hosts:** 172.27.224.11, 172.27.224.70, 172.27.224.250, 172.27.224.251
* **Total protocols:** ARP, BJNP, BROWSER, DHCP, DHCPv6, ICMPv6, IGMPv3, LLMNR, Modbus/TCP, RARP,  STP, TCP, UDP
* **Total attacks:** none


**ARP-based, Man-in-the-Middle attack**

* **Number of PCAPs:** 22
* **Total number of packets:** 4 161 258
* **Total timeline:** 2018-08-23 18:57:01.789547 UTC - 2018-09-04 02:08:55.041070 UTC
* **Total involved hosts:** 172.27.224.70 (00:0c:29:9d:9e:9e), 172.27.224.80 (00:0c:29:e6:14:0d), 172.27.224.250 (00:80:f4:09:51:3b), 172.27.224.251 (48:5b:39:64:40:79)
* **Total protocols:** ARP, BROWSER, DHCP, DHCPv6, ICMP, ICMPv6, IGMPv3, IRC, LLMNR, Modbus/TCP, STP, TCP, UDP
* **Total attacks:** mitm-change, mitm-read


**Modbus query flooding**

* **Number of PCAPs:** 44
* **Total number of packets:** 19 861 222
* **Total timeline:** 2018-05-22 10:00:59.923334 UTC - 2018-08-14 17:52:17.836726 UTC
* **Total involved hosts:** 172.27.224.50 (Source), 172.27.224.70 (Source), 172.27.224.80 (Source),  172.27.224.250 (Destination)
* **Total protocols:** ALLJOYN-NS, AMQP, AMS, ARP, ASAP, ASF, ATMTCP, AX4000, BACnet-APDU, BEEP, BFD Control, BJNP, BROWSER, BitTorrent, CAPWAP-Control, CLASSIC-STUN, Chargen, DAYTIME, DB-LSP, DCERPC, DHCP, DHCPv6, DIAMETER, DISTCC , DNS, DRDA, ECATF, ECHO, ECMP, ELCOM, EPM, Elasticsearch, FTP, GIOP, Gearman, Gnutella, HTTP, HTTP/XML, HTTP2, IAX2, ICMP, ICMPv6, ICP, IGMPv3, IPA, IPDC, IPSICTL, IPv4, IRC, ISAKMP, ISystemActivator, KPASSWD, KRB4, L2TP, LANMAN, LLMNR, MAC-Telnet, MDNS, MEMCACHE, MIH, Messenger, Modbus/TCP, NAT-PMP, NBNS, NBSS, NDMP, NTP, Nano Bootstrap, Netsync, OMAPI, Omni-Path, OpenVPN, PMPROXY, PTP/IP, Portmap, R3, RADIUS, REMACT, RIPv1, RIPv2, RSIP, RTSP, RX, SABP, SAMR, SIP, SMB, SMB Mailslot, SMB Pipe, SMB2, SNMP, SRVLOC, SSDP, SSH, SSL, SSLv3, STP, TCP, TFP over TCP, TFTP, TLSv1, TLSv1.1, TLSv1.2, TPKT, UDP, VNC, WOW, X11, XDMCP, synergy
* **Total attacks:** Modbus query flooding


**ICMP flooding**

* **Number of PCAPs:** 33
* **Total number of packets:** 10 092 395
* **Total timeline:** 2018-05-21 09:54:56.811018 UTC - 2018-08-09 00:57:02.800427 UTC
* **Total involved hosts:** 172.27.224.250 (Destination), many more IP addresses from the full range of IP addresses (Source)
* **Total protocols:** ARP, BJNP, BROWSER, DHCP, DHCPv6, ICMP, ICMPv6, IGMPv3, IRC, LLMNR, Modbus/TCP, RARP, STP, TCP, UDP
* **Total attacks:** ICMP flooding


**TCP SYN flooding**

* **Number of PCAPs:** 33
* **Total number of packets:** 6 849 825
* **Total timeline:** 2018-05-21 15:32:57.012079 UTC - 2018-08-06 17:44:39.865941 UTC
* **Total involved hosts:** 172.27.224.250 (Destination), many more IP addresses from the full range of IP addresses (Source)
* **Total protocols:** 104apci, ALLJOYN-NS, AMQP, AMS, ANSI C12.22, ARP, ASAP, ASF, ATMTCP, AX4000, BACnet-APDU, BEEP, BFD Control, BJNP, BROWSER, BitTorrent, CAPWAP-Control, CLASSIC-STUN, CVSPSERVER, Chargen, DAYTIME, DB-LSP, DCERPC, DHCP, DHCPv6, DIAMETER, DISTCC , DNS, DRDA, ECATF, ECHO, ECMP, ELCOM, Elasticsearch, FTP, GIOP, GTPv2, Gearman, Gnutella, HTTP, HTTP/XML, HTTP2, IAX2, ICAP, ICMP, ICMPv6, ICP, IGMPv3, IPA, IPDC, IPSICTL, IPv4, IRC, ISAKMP, ISystemActivator, KNET, KPASSWD, KRB4, L2TP, LANMAN, LLMNR, MAC-Telnet, MDNS, MEMCACHE, MIH, MQTT, MSNMS, Modbus/TCP, NAT-PMP, NDMP, NTP, Nano Bootstrap, Netsync, OMAPI, Omni-Path, OpenVPN, PMPROXY, PPTP, PTP/IP, Portmap, R3, RADIUS, RIPv1, RIPv2, RMI, RSIP, RTSP, RX, SABP, SAMR, SIP, SMB, SMB Pipe, SMB2, SNMP, SRVLOC, SSDP, SSH, SSHv2, SSL, SSLv3, STP, Socks, TCP, TFP over TCP, TFTP, TLSv1, TLSv1.1, TLSv1.2, TPKT, UDP, VICP, VNC, WOW, X11, XDMCP, ZEBRA, giFT, kismet, synergy
* **Total attacks:** TCP SYN flooding


## [WireShark SampleCaptures](https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures)
WireShark provides many PCAP capture files in its wiki page. Some packet capture files are described in the following sections.

### [SSL with decryption keys](https://git.lekensteyn.nl/peter/wireshark-notes/tree/tls)
Wireshark provides a list of PCAP files together with the decryption keys. Some PCAPs from the list are described in the following part of this section. The description and source of the PCAP file is retrieved from the Wireshark wiki page.

**rsasnakeoil.cap**

* **Description:**  SSL encrypted HTTPS traffic, example taken from the dev mailinglist, RSA key available
* **Number of packets:** 58
* **Timeline:** 2006-08-24 09:04:15.842911 UTC - 2006-08-24 09:04:28.211338 UTC
* **Involved hosts:** 127.0.0.1
* **Protocols:** HTTP, SSLv2, SSLv3, TCP


**dump.pcapng**

* **Description:** a openssl's s_client/s_server HTTP GET request over TLSv1.2 with 73 different cipher suites, generated using the openssl-connect
* **Number of packets:** 1 095
* **Timeline:** 2013-09-15 21:52:16.72595 UTC - 2013-09-15 21:52:17.696039 UTC
* **Involved hosts:** 127.0.0.1
* **Protocols:** SSLv2, TCP, TLSv1.2


**mysql-ssl.pcapng**

* **Description:** MySQL over TLSv1, PCAP from Peter Wu's Wireshark-notes, pre-master keys are available in capture comments; server with MariaDB, database testdb, queries (INSERT, SELECT, deliberate disallowed USE mysql and more), more description can be found on [commit description](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/mysql-ssl.pcapng?id=8cfd2f667e796e4c0e3bdbe117e515206346f74a)
* **Number of packets:** 59
* **Timeline:** 2015-01-29 10:39:58.578402281 UTC - 2015-01-29 10:40:33.092194163 UTC
* **Involved hosts:** 127.0.0.1
* **Protocols:** MySQL, TCP, TLSv1.2


**pop-ssl.pcapng**

* **Description:** POP, PCAP from Peter Wu's Wireshark-notes, pre-master keys are available in capture comments; after handshake, "POPA" followed by renegotiation, "POPA" and "QUIT", more description can be found on [commit description](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/pop-ssl.pcapng?id=860c55ba8449a877e21480017e16cfae902b69fb)
* **Number of packets:** 38
* **Timeline:** 2015-01-30 14:49:01.890849939 UTC - 2015-01-30 14:49:13.645704037 UTC
* **Involved hosts:** 127.0.0.1
* **Protocols:** POP, TCP, TLSv1.2


**smtp-ssl.pcapng**

* **Description:** SMTP, PCAP from Peter Wu's Wireshark-notes, pre-master keys are available in capture comments; "EHLO lekensteyn" was typed and triggered a renegiotation with "R" (which resulted in an error), more description can be found on [commit description](https://git.lekensteyn.nl/peter/wireshark-notes/commit/tls/smtp-ssl.pcapng?id=9615a132638741baa2cf839277128a32e4fc34f2)
* **Number of packets:** 38
* **Timeline:** 2015-01-30 11:31:42.005931161 UTC - 2015-01-30 11:32:41.025768841
* **Involved hosts:** 127.0.0.1
* **Protocols:** SMTP, TCP, TLSv1.2
