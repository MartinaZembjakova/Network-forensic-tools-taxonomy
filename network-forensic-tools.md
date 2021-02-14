# Network forensic tools

It is useful to have an overview of tools that can be used in network forensics with its basic description. The overview of available tools helps to choose the suitable tool that can assist in obtaining the information, collecting and analyzing the evidence, or creating the reports.

This website describes some network tools that can be used during network forensics. This overview includes both commercial and free to use tools. Some older tools are also included.
## Acunetix Web Vulnerability Scanner 

**Links:** [official website](https://www.acunetix.com/)

An Acunetix is a complete web application security testing solution that includes a web vulnerability scanner. It is a commercial tool and the pricing is based on the number of scanned websites. The Acunetix can be used both standalone and as part of complex environments. This product offers built-in vulnerability assessment, vulnerability management, and integration with software development tools. 

It can be deployed locally on Linux, Mac OS, and Microsoft Windows operating systems. In addition to the locally deployed product, the cloud version is also supported. 

## Aircrack-ng

**Links:** [official website](https://www.aircrack-ng.org/)

An Aircrack-ng is an open-source that was started in 2006 and is still developing. It is a suite of tools to assess WiFi network security. The Aircrack-ng can run on Windows and Linux machines. It also works on OS X, FreeBSD, OpenBSD, NetBSD, Solaris and eComStation 2.

There are four areas of WiFi security, the aircrack-ng focuses on:

* *Monitoring* - packet capture and data export for further analysis,
* *Attacking* - replay attacks, deauthentication, fake AP and others via packet injection,
* *Testing* - checking WiFi cards and driver capabilities (capture and injection),
* *Cracking* - WEP and WPA PSK.

The Aircrack-ng suite consists of the following tools - airbase-ng, aircrack-ng, airdecap-ng, airdecloak-ng, airdriver-ng, airdrop-ng, aireplay-ng, airgraph-ng, airmon-ng, airodump-ng, airolib-ng, airserv-ng, airtun-ng, besside-ng, dcrack, easside-ng, packetforge-ng, tkiptun-ng, and wesside-ng. The other tools include WZCook, ivstools, Versuck-ng, buddy-ng, makeivs-ng, and kstats.

## AirPcap/Riverbed AirPcap

**Links:** [official website](https://support.riverbed.com/content/support/software/steelcentral-npm/airpcap.html)

An Riverbed AirPcap, formely AirPcap, is a USB-based adapter that captures 802.11 wireless traffic. The captured data can be analysed by other analysis tools like Wireshark. The only supported platform for AirPcap is Windows.

The AirPcap Product Family contains products like AirPcap
Classic, AirPcap Tx, and AirPcap Nx. All these products can capture full 802.11 frames, are fully integrated with Wireshark, have open API, support multi-channel monitoring (with two or more adapters), and have USB dongle form. Packet transmission is available only on AirPcap Tx and AirPcap Nx. Frequency bands for AirPcap Classic and AirPcap Tx are 2.4 GHz (b/g), for AirPcap Nx 2.4 and 5 Ghz (a/b/g/n).

## Angry IP Scanner

**Links:** [official website](https://angryip.org/), [documentation](https://angryip.org/documentation/)

An Angry IP Scanner, also known as ipscan, is free and open-source network scanner. The aim of this tool is to scan IP addresses and ports, the results can be saved in many supported formats including CSV, TXT, XML or IP-Port list. It also support many plugins that can provide the user with the detailed information about scanned nodes like hostname, MAC address, or NetBIOS information. Other features include favorite IP address ranges, web server detection, customizable openers and so on

This network tool can be run on many platforms including Linux, Windows, and Mac OS X.

The advantages of the Angry IP Scanner include user-friendly interface, it is a very fast IP address and port scanner, it doesn't require any installation, and it uses multithreaded approach for increasing the scanning speed

## Argus

**Links:** [official website](openargus.org)

An Argus is the network flow system, developed by Carter Bullard in the early 1980's at Georgia Tech. The Argus Project is an open source project focused on proof of concept demonstrations of all aspects of large scale network awareness derived from network flow data. It is a real time flow monitor that is designed to perform comprehensive data network traffic auditing.

The Argus's main goal is to process captured packets or on the wire into the network flow data. It deals with the following issues of network flow data: scale, performance, applicability, privacy, and utility.

The Argus system consists of two parts:

* *argus* - a packet processing network flow sensor that generates Argus data,
* *argus-clients* - a collection of argus data processing programs.

The Argus Project efforts include: data generation, transport, collection, storage, analytics, and various metadata enhancements. 

The Argus is multi-platformed tools, it supports more than 24 platforms. The argus-clients focuses on data processing including data distribution, collection, filtering, aggregation, binning, minimization, privacy, metadata enhancement, geolocation, net-spatial location, compression, anonymization, graphing, databases, analytics, storage, and error correction.

## ARP

**Links:** [Linux man page](https://linux.die.net/man/8/arp), [Windows documentation page](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/arp)

An arp is a command-line network tool that is used to display and modify the ARP cache. This command is available for many platforms, including Linux, Windows, and MacOS systems. The main features include displaying ARP cache for single interface or all interfaces, deleting and adding an address mappings.

## Bless

**Links:** [GitHub repository](https://github.com/afrantzis/bless)

A Bless is an open-source binary HEX editor.

The main target platform for this tool is GNU/Linux. However, since all used libraries are cross-platform, the Bless is be able to run also on other platforms like BSD, Solaris, and Win32.

Some of the main features include:

* efficient editing of large data files,
* raw disk editing,
* mmultilevel undo - redo operations, fast find and replace operations, multi-threaded search and save operations,
* conversion table,
* export to text and html (others with plugins),
* extensibility with plugins.


## Bricata

**Links:** [official website](https://bricata.com/)

A Bricate is a commercial end-to-end network detection and response platform. It fuses signature inspection, stateful anomaly detection, and machine learning-powered malware conviction. It provides the real-time detection, response, hunting and defending against threats.

## Bro/Zeek

**Links:** [official website](https://zeek.org/), [documentation](https://docs.zeek.org/en/current/intro/index.html), [GitHub repository](https://github.com/zeek/zeek)

A Zeek, formely Bro, is a network security monitoring tool. It is a passive, open-source network traffic analyzer. This tool can be installed in the Unix and MacOS systems. 

In addition to acting as a security monitor that inspects all traffic data and searches for abnormal activity, this tool also provides a wide range of traffic analysis tasks, including performance measurements. The Zeek also provides a management framework, named ZeekControl.

Zeek's architecture consists of the event engine and the policy script interpreter. The event engine receives the packets from the network and produces events read by the policy script interpreter. The policy script interpreter then generates logs and other notifications. The script interpreter executes a set of event handlers written in Zeek's custom scripting language.

The user manual of the tool provides also the examples and use cases of common using the Zeek tool.

Some of the features, the Zeek provides, include:

* real-time and offline analysis,
* cluster support,
* support for many application-layer protocols and analysis of file content exchanged over application-layer protocols,
* tunnel detection and analysis,
* support for IDS-style pattern matching,
* event-based programming model,
* alternative backends for ElasticSearch and DataSeries.


## CapAnalysis

**Links:** [official website](https://www.capanalysis.net/ca/)

A CapAnalysis is an open-source web-based capture file viewer that can work with more than one PCAP file. It performs indexing of data set of PCAP files and visualizes their contents in many forms - flows, statistics, source IPs, destination IPs, per hour statistics, Geo map, protocols, and timeline. The data or flows can also be filtered according to the IP, port, protocol, country, data volume, or date. This tool is available for Linux systems, like Debian or Ubuntu.

## CapLoader

**Links:** [official website](https://www.netresec.com/?page=CapLoader)

A CapLoader is a Window-based commercial tool that can handle large amounts of captured network traffic. It performs indexing of capture files and visualizes their contents as a list of TCP and UDP flows. It provides filtering of the packets and exporting packets/flows into the packet analyzer tool.

In addition to the professional edition, the 30\,days trial is also available. This trial version can handle 500 GB of captured data, supports pcapng and IPv6, can filter keywords and provides keywords string search. Other features of the trial version include flow transcript view, DNS parser, initial RTT calculation, network packet carving, input filter (BPF), display filter (BPF), hide flows in GUI, and service regularity/period detection. The professional version does not have a limit for PCAP files, and in addition to the features of the trial edition, it provides Alexa and Cisco Umbrella top 1M lookup, port independent
protocol identification (PIPI), OS fingerprinting, Geo-IP localization, ASN lookup, regular expression (regex) search, select flows from the log file or PCAP file, and Wireshark style Coloring.

## Carnivore

**Links:** [Open Carnivore article from web archive](https://web.archive.org/web/20141110081046/http://opencarnivore.org/), [Independent Review of the Carnivore System](https://epic.org/privacy/carnivore/carniv_final.pdf)

A Carnivore, also known as DCS1000, is an FBI software-based tool used to examine all IP packets on an Ethernet and record only those packets or packet segments that meet very specific parameters. Therefore this tool can be classified as a packet sniffer.

This tool can by installed by properly authorized FBI agents on a particular Internet Service Provider’s (ISP) network. This software system is used together with a tap on the ISP’s network. The aim is to intercept, filter, seize and decipher digital communications on the Internet.

This tool is not available for download.

## Check Point IPS-1/IPS

**Links:** [official website](https://www.checkpoint.com/products/intrusion-prevention-system-ips/), [IPS-1 Sensor Administration Guide](http://supportcontent.checkpoint.com/documentation_download?ID=10505), [The Check Point IPS Solution Administration Guide](https://sc1.checkpoint.com/documents/R76/CP_R76_IPS_AdminGuide/12742.htm)

A Check Point IPS-1 is an IPS that uses IPS-1 Sensors that can be placed on the network perimeter or at any location of internal network. 

The advantages of IPS-1 may include:

* Unified security management,
* Mission-critical protection against known and unknown attacks, 
* Granular forensic analysis,
* Flexible deployment,
* Confidence Indexing.


The Check Point IPS is available in two deployment methods: IPS Software Blade, and IPS-1 Sensor. 

The Check Point IPS is part of the Check Point Next Generation Firewall. It is a commercial IPS that detect or prevent attempts to exploit weaknesses in vulnerable systems or applications.

## chkrootkit

**Links:** [official website](http://www.chkrootkit.org/)

A chkrootkit is a free tool that locally checks for signs of a rootkit. This is a multiplatform tool that can be run on Linux, Windows, MacOS, Solaris, or BSD systems.

## Cisco FireSIGHT System

**Links:** [Sourcefie 3D System User Guide](https://www.cisco.com/c/dam/en/us/td/docs/security/sourcefire/3d-system/53/Sourcefire_3D_System_User_Guide_v53.pdf), [FireSIGHT System User Guide](https://www.cisco.com/c/en/us/td/docs/security/firesight/541/user-guide/FireSIGHT-System-UserGuide-v5401/Intro-Preface.html)

A Cisco FireSIGHT System, formerly SourceFire 3D System, is an integrated suite of network security and traffic management products. The appliances can be used in switched, routed, or hybrid environments. The products can be deployed either as software-based appliances or on purpose-built platforms. It is possible also to configure NAT, establish VPN tunnels between endpoints, configure bypass interfaces, aggregated interfaces, fast-path rules, and strict TCP enforcement.

FireSIGHT components include Redundancy and Resource Sharing, Network Traffic Management, FireSIGHT, Access Control, SSL Inspection, Intrusion Detection and Prevention, Advanced Malware Protection and File Control, and Application Programming Interfaces. 

Some of the managed devices are Series 2 and Series 3 Managed Devices (Cisco FirePOWER 7000 Series and 8000 Series devices), 64-Bit Virtual Managed Devices, Cisco NGIPS for Blue Coat X-Series, and Cisco ASA  FirePOWER Devices.

## Corero Network Security

**Links:** [official website](https://www.corero.com/products/)

The Corero provides network security products focused on DDoS protection. The company's products include:
 * *SmartWall DDoS Protection* - a real-time, automatic, highly acalable DDoS protection solution with multiple deployment options (on-premise, cloud, hybrid),
* *SecureWatch Managed DDoS Protection Services* - a SmartWall deployment managed by Corero experts.

## DeepSee

**Links:** [Symantec End of Life](http://www.dhitech.co.kr/Service_Resource/pdf/SecurityAnalyticsHardware.pdf)

A DeepSee was a proprietary network security tool developed by Solera Networks, acquired by NortonLifeLock. 

Solera DS 5150 was an appliance for high-speed data capture, complete indexed record of network traffic, filtering, regeneration, and playback.

According to Symantec's *Security Analytics Hardware EOL (End of Life)*, all DeepSee hardware already reached EOL.

## dig

**Links:** [official website](https://www.isc.org/bind/)

A dig is a BIND's command line DNS diagnostic tool. BIND 9 is an open-source full-featured DNS system. It is available for Windows and Linux platforms.

## DoHlyzer

**Links:** [GitHub repository](https://github.com/ahlashkari/DoHlyzer)

A DoHlyzer is a network flow tool that detects and characterizes DoH (DNS over HTTPS) traffic. It can be run using Python, and therefore it is a multiplatform tool.

The DoHlyzer is a set of tools that consists of the following modules:

* *Meter* - captures packets or reads PCAP file, groups packets into flows, and extracts statistical and time-series features for traffic analysis,
* *Analyzer* - creates the DNN models and benchmark them against the aggregated clumps file (can be created by the Meter module),
* *Visualizer* - visualizes the clumps files.


## Dshell

**Links:** [GitHub repository](https://github.com/USArmyResearchLab/Dshell)

A Dshell is an open-source network forensic analysis framework written in Python. This tool works with plugins that can be run on the capture file or live on an interface. Key features include deep packet analysis, robust stream reassembly, IPv4 and IPv6 support, and custom output handlers. It also supports elasticsearch to store the output.

The plugins can be chained. The available plugins include dhcp, dns, filter, flows, ftp, http, malware, misc, nbns, portscan, protocol, ssh, ssl, tftp, visual, voip, and wifi.

## dumpcap

**Links:** [official website](https://www.wireshark.org/docs/man-pages/dumpcap.html)

A Dumpcap is a part of the Wireshark distribution. It is a network traffic dump tool that captures packet data and stores them according to the specified parameters.

## E-detective

**Links:** [official website](http://www.edecision4u.com/E-DETECTIVE.html)

An E-detective is a real-time LAN Internet monitoring tool developed by the Decision Group. This tool's function is to capture and decode network packets, and it reconstructs them and saves them in the original format. Thanks to the reconstruction of the data and saving it in the original format, the E-detective user can see the data in the same way seen on the network. Despite using this tool during the forensic analysis and investigation, it can also be used in auditing, record keeping, legal and lawful interception, and others.

It can be deployed as a temporary deployment (a tactical standalone system) or permanently deployment (Private Enterprises).

The range of the protocol the E-detective can decode and reconstruct is more than 140 different protocols, including

* email and webmail protocols (POP3, SNMP, IMAP, Yahoo Mail, Windows Live Hotmail, Gmail),
* Instant Messaging protocols (Yahoo, MSN, ICQ, QQ, Google Talk, IRC, UT Chat Room, Skype),
* File Transfer protocols (FTP, P2P),
* Social media sites (Facebook, Twitter),
* Telnet, Online games, HTTP, VOIP, mobile service protocols, and more.


The advantages include that this tool can also work with the HTTPS traffic when the HTTPS module is enabled. When using the HTTPS decoder, the user's login and password information are captured. Furthermore, the data can be archived using the automated FTP service, and also they can be downloaded as an ISO file. Moreover, this tool can work with the other reporting tools, and therefore can provide the users with professional reports like reports with Up-Down View, Total Throughput Statistical Report, Network Service Report (Daily, Weekly basis), Top Websites, and others. Additionally, there are also available search functions like Free Text Search, Conditional Search, Similar Search, and Association with Relationship Search. Alert and notification functions are also provided. Some other functions include Bookmark, Capture File List (Comparing the content of two files), Online IP List, Authority Assignment, Syslog Server, hashed export (backup), and file content comparison.

## EmailTrackerPro

**Links:** [official website](http://www.emailtrackerpro.com/)

An EmailTrackerPro is an email tracker and spam filter tool. It is a commercial tool available for the Windows platform.

The main functions of this tools are

* *tacking the email* - providing the location of the email (usually displayed on the world map), the tracing of the email is done using the email header information,
* *report abuse* - ,a more proactive approach to dealing with spam, EmailTrackerPro provides a platform that auto-generates an abuse report,	
* *spam filter* - stopping spam before it reaches the inbox.

## Enterasys IPS

**Links:** [official website (Extreme Network IPS)](https://www.netsolutionstore.com/IPS.asp)

The Enterasys was acquired by *Extreme Networks* on September 2013.

The IPS system of *Extreme Networks* company, Extreme Networks Intrusion Prevention System (IPS), is an IPS system that is able to gather evidence of an attacker’s activity, remove the attacker’s access to the network, and reconfigure the network to resist the attacker’s penetration technique.

## EtherApe

**Links:** [official website](https://etherape.sourceforge.io/)

An EtherApe is an open-source graphical network monitoring tool. This tool is available for UNIX systems. It can work with the live data or with a tcpdump captured file. The aim is to display the network traffic graphically - node and link color show the most used protocol. There can be displayed traffic within their network, end to end IP, or port to port TCP.

Moreover, there is possible to select the level of the protocol stack to concentrate on. The displayed data can be refined using a network filter. Furthermore, there is able to display averaging and node persistence times. This tool also provides TCP statistics and node statistics that can also be exported.

## Ethereal/Wireshark

**Links:** [official website](https://www.wireshark.org), [user guide](https://www.wireshark.org/download/docs/user-guide.pdf)

A WireShark, formerly Ethereal, is an open-source network protocol analyzer. It provides users with what is happening on the network at a microscopic level. It can work with the live captured data or already captured data in many supported captured formats.

Other features of Wireshark include filtering packets according to the specified filters, searching for packets on many criteria, saving and exporting captured traffic data, and creating statistics.

It is the multiplatform tool that can be run on Windows, MacOS, UNIX, Linux, BSD, Solaris, and many other systems.

## findject.py

**Links:** [official website](https://www.netresec.com/?page=findject)

A findject.py is an open-source python script that can detect TCP packet injection attacks in HTTP sessions. Unlike the IDS solutions, this script can also properly detect Man-on-the-Side (MOTS) attacks. This script analyzes PCAP files and prints the output of gained injections.

## findsmtpinfo.py

**Links:** [repository with the program from web archive](web.archive.org/web/20200522224019/http://forensicscontest.com/contest02/Finalists/Jeremy_Rossi/)

A findsmtpinfo.py is a network tool written for the Network Forensic Puzzle #2 Contest by Jeremy Rossi. This tool reads a PCAP file, decodes authentication data (username and password), gathers email information, stores attachments (decompresses them if in compressed format), checks the MD5sum, and creates a report of the SMTP information.

## flow-tools

**Links:** [Linux man page](https://linux.die.net/man/1/flow-tools)

A flow-tools is a set of network tools for working with NetFlow data. The function is to collect, send, process, and generate reports from NetFlow data. 

It can be deployed as a package for Linux systems. It can be used on a single server or distributed to multiple servers.

The flow-tools distribution include the following tools: 

* *flow-capture* - collect, compress, store, and manage disk space for exported flows,
* *flow-cat* - concatenate flow files,
* *flow-dscan* - tool for detecting some types of network scanning and DoS attacks,
* *flow-expire* - expire flows,
* *flow-export* - export data,
* *flow-fanout* - replicate NetFlow datagrams to unicast or multicast destinations,
* *flow-filter* - filter flows and can be used with other programs to generate reports,
* *flow-gen* - generate test data,
* *flow-header* - display meta information in flow file,
* *flow-import* - import data,
* *flow-merge* - merge flow files (in chronological order),
* *flow-receive* - receive exports using the NetFlow protocol (without storing to disk),
* *flow-report* - generate reports for NetFlow data sets,
* *flow-send* - send data using the NetFlow protocol,
* *flow-split* - split flow files,
* *flow-tag* - tag flows for and can be used to group flows and generate reports,
* *flow-xlate* - perform translation on some flow fields.

## FlowTraq

**Links:** [official website](https://www.flowtraq.com), [FlowTraq Exporter product website](https://www.flowtraq.com/product/flow-exporter/)

A FlowTraq is a commercial flow record analysis tool developed by ProQueSys, lately acquired by Riverbed. It offers two deployment models: cloud and on-premise solution.

This tool can recognize DDoS and other attacks in real time and trigger automated scrubbing, protect sensitive information, defend the network from malicious botnets, and improve the network forensics capabilities.

The FlowTraq supports all flow formats, that can be mixed as the sources. It can sniff traffic directly, generate flow records, filter, search, sort, and produce reports.

The FlowTraq also provides the tool named the FlowTraq Exporter. The FlowTraq Exporter is a free software flow exporter that exports existing PCAP traffic data files into flow format data. It can be run on Windows, Linux and BSD systems.

## Forensics Investigation Toolkit (FIT)

**Links:** [official website](www.edecision4u.com/FIT.html)

The Forensics Investigation Toolkit (FIT) is a licensed tool developed by the *Decision Group Inc.* This toolkit is available for Windows systems and can analyze network packet data. These data can be read from a PCAP file or real-time captured. The FIT provides a graphical user interface. The other features include full-text searching, bookmarking, immediate parsing and reconstruction of the raw data into categories, WhoIS and Google Map integration, association analysis, and export of the analyzed data.

## Gnetcast (GNU Netcat)

**Links:** [official website](http://netcat.sourceforge.net/)

A Gnetcast is a GNU rewrite of netcat tool (netcat tool is described in its own section). 

It is fully compatible with the netcat tool and portable. The supported platforms include Linux, FreeBSD, NetBSD, Solaris, and MacOS.

## Haka

**Links:** [official website](http://www.haka-security.org/), [user guide](http://doc.haka-security.org/haka/release/v0.3.0/doc/user/userindex.html)

A Haka is an open-source security-oriented framework that allows to describe protocols and apply security policies on captured traffic or live on interfaces. The two main features of the Haka are writing security rules and specifying network protocols and their underlying state machine. 

The Haka project provides modules for packet capturing, alerting, and logging. It also provides a tool suite that consists of the following programs:

* *haka* - the main program of the collection, can capture packets (pcap or nfqueue) and filter or alter them according to the specified Haka policy file, usually launched as a daemon,
* *hakactl* - allows to control a running haka daemon (displays haka status, start or stop the haka daemon, show logs, debug haka rules),
* *hakapcap* - a tool to quickly apply a Haka policy file to a pcap file.


A Hakabana is a monitoring tool to visualize network traffic going through Haka in real-time using Kibana and Elasticsearch. Both Haka and Hakabana can be installed through Debian package, Tarball install, or Live ISO.

## HoneyBadger

**Links:** [official website (documentation)](https://honeybadger.readthedocs.io/en/latest/), [GitHub repository](https://github.com/david415/HoneyBadger)

A HoneyBadger is an open-source TCP stream analysis tool for detecting and recording TCP injection attacks (Quantum Insert detector). It performs passive analysis of TCP traffic and detects evidence of MOTS attacks. It can work with PCAP files or analyze an interface.

The HoneyBadger provides a *honeybadgerReportTool* that is a report deserialization tool. It displays a dump output (ASCII and hex).

## HP TrippingPoint IPS

**Links:** [official website](https://www.trendmicro.com/en_us/business/products/network/intrusion-prevention.html)

HP TrippingPoint company was acquired by *Trend Micro* on October 2015.

The Trend Micro Intrusion prevention consists of TippingPoint solutions: TippingPoint Threat Protection System, Centralized Management and Response, and Threat Intelligence. Trend Micro TippingPoint Threat Protection System Family provides real-time detection, enforcement, and remediation without compromising security or performance. Key features include Cloud Network Protection, On-Box SSL Inspection, Performance Scalability, Flexible Licensing Mode, Real-Time Machine Learning, Enterprise Vulnerability Remediation (eVR), Advanced Threat Analysis, High Availability, Integrated Advanced Threat Prevention, Asymmetric Traffic Inspection, Agility and Flexibility, Best-in-Class Threat Intelligence, Virtual Patching, Support for a Broad Set of Traffic Types, and Centralized Management.

## IBM Security NIPS

**Links:** [documentation](https://www.ibm.com/support/knowledgecenter/SSB2MG_4.6.2/com.ibm.ips.doc/NIPS_product_landing.htm)

An IBM Security Network Intrusion Prevention System (NIPS) is an IPS system developed by the IBM company. The IBM Security NIPS appliances are purpose-built, Layer 2 network security appliances. The aim is to block intrusion attempts, denial of service (DoS) attacks, malicious code, backdoors, spyware, and peer-to-peer applications.

## ifconfig

**Links:** [Linux man page](https://linux.die.net/man/8/ifconfig)

An ifconfig is a Linux command line network tool used for configuring a network interface. This command can be replaced by commands *ip addr* and *ip link*. Without specifying arguments the ifconfig displays the status of the currently active interfaces.

## Index.dat analyzer

**Links:** [official website](https://www.systenance.com/indexdat.php)

An Index.dat is a free network tool used for viewing, examining, and deleting contents of index.dat files. Index.dat files contain all online activity information, like searching history, visited websites, and accessed URLs, files, and documents.

## InfiniStream (nGeniusONE)

**Links:** [official website (nGeniusONE)](netscout.com/product/ngeniusone-platform), [product decription (Infinistream appliance)](https://www.netscout.com/sites/default/files/2015/06/netscout_ql_infinistream_appliance.pdf)

An InfiniStream is an intelligent deep packet capture and analysis appliance that is a foundation for a nGeniusONE platform. This is a proprietary tool for customized Linux systems, owned by the NetScout Systems company.

The features of the InfiniStream appliances include real-time packet flow-based data monitoring, packet storage for forensics (back-in-time analysis), passive and non-intrusive capturing all network traffic and generating metrics, ASI technology (for high performance, deep packet inspection, and analysis), scalable architecture, working also with packet crossing the wire, and flexible range of appliances.

## IP Address Tracker and IP Address Manager

**Links:** [official website (IP Address Tracker)](https://www.solarwinds.com/free-tools/ip-address-tracker), [official website (IP Address Manager)](https://www.solarwinds.com/ip-address-manager)

An IP Address Tracker is a free network tool that can scan, track, and manage IP addresses and obtain detailed IP histories and event logs. It is a reduced feature set version of commercial tool IP Address Manager (IPAM) developed by SolarWinds.

Key features of IP Address Tracker include managing up to 254 IP addresses, detecting IP conflicts, getting detailed IP histories and event logs, getting detailed reporting for IP addresses, and monitoring subnets.

The licensed tool IPAM can, in addition to the features of IP Address Tracker, manage up to 2 million IP addresses, monitor DNS and DHCP, assess DHCP, DNS, and IP address role-based task permissions, and administer integrated DNS and DHCP. The Solarwinds provides the free 30 days trial of IPAM.

## IPFIX

**Links:** [documentation (RFC)](https://tools.ietf.org/html/rfc7011)

An IPFIX (Internet Protocol Flow Information Export) is a protocol that transmits traffic flow information over the network. The architecture contains a collector (Collecting Process) and an exporter (Exporting Process). It defines how IP flow information is to be formatted and transferred from an exporter to a collector. It supports TCP, UDP, and SCTP as transport protocols. The IPFIX provides the following three record formats: the Template Record format, the Options Template Record format, and the Data Record format.

## IPTraf

**Links:** [official website](http://iptraf.seul.org/)

An IPTraf is an open-source network monitoring utility for IP networks for Linux systems. It intercepts packets on the network and analyzes the IP traffic. 

The provided information about the IP traffic include: 

* Total, IP, TCP, UDP, ICMP, and non-IP byte counts,
* TCP/UDP/OSPF source and destination information (addresses and ports),
* TCP packet counts, byte counts, flag statuses,
* ICMP type information,
* TCP/UDP service statistics, LAN station statistics,
* Interface packet counts, IP checksum error counts, and activity indicators.

## Iris

**Links:** [product website](https://www.malavida.com/en/soft/iris-network-traffic-analyzer/#gref), [product description](https://www.techrepublic.com/article/monitor-the-data-packets-on-your-network-with-eeyes-iris/)

An Iris, formerly SpyNet CaptureNet, is a network traffic analyzer developed by eEye Digital Security, acquired by Beyond Trust. It is a commercial tool for the Windows platform that analyzes all the traffic of a network according to filters. It can capture, analyze and show the network data.

This tool is designed to take the guesswork out of bandwidth monitoring. It can scan the network packets for searching certain words or monitor specific IP addresses or users. When it detects packets that meet the criteria, it can reconstruct the website or notify when the specific program was used. The Iris is also able to read sent emails, including its attachments.

## KisMAC

**Links:** [official website](https://kismac-ng.org/)

A KisMAC is an open-source WiFi scanner that identifies WiFi networks around the device, including hidden, cloaked, and closed ones. This tool is available for MacOS systems.

The other features of the KisMAC include: 

* information about the logged users on the network (MAC Address, IP address, signal strength),
* supports mapping. GPS, 802.11b/g frequency, and Kismet drone captures,
* PCAP import and export,
* Different attacks against encrypted networks, Deauthentication attacks.


The KisMAC is no longer being updated or maintained. The latested version was released in 2011.

## Kismet

**Links:** [official website](https://www.kismetwireless.net/)

A Kismet is an open-source wireless network and device detector, sniffer, wardriving tool, and WIDS framework. It conatains Python plugins like kismetdb database module, kismetrest module, or kismetexternal module.

The Kismet is a multiplatformed tool that can be run on Linux, Windows, and MacOS systems. It works with Wi-Fi interfaces, Bluetooth interfaces, and some hardware interfaces like SDR hardware.

## Log Analyzer

**Links:** [official website](https://www.solarwinds.com/log-analyzer)

Log Analyzer is a commercial network tool for log and event collection and analysis. It is integrated with the Solarwinds Orion platform. The other key features include powerful search and filter, real-time log stream, event log tagging, and flat log file ingestion. There is also available free 30 days trial.

## LogRhythm NetMon and LogRhythm NetMon Freemium

**Links:** [official website (LogRhythm NetMon)](https://logrhythm.com/products/logrhythm-netmon/), [official website (LogRhythm NetMon Freemium)](https://logrhythm.com/products/logrhythm-netmon-freemium/)

A LogRhythm NetMon is a commercial SIEM network monitoring tool that helps detect, stop, and recover from attacks. It provides real-time visibility, security analytics, and network-based incident response. The features include unstructured search across all network data, deep packet analytics, full packet capture and SmartCapture, automatic recognition of applications, continuous search-based alerting, data forwarding via Syslog, data processing up to 10 Gbps, unlimited packet capture storage, and metadata indexing up to 30 days.

A LogRhythm NetMon Freemium is a free version of the LogRhythm NetMon tool. The main functions are the same. There are only limits on processing, packet storage, and data forwarding - it is not able to forward data via Syslog, data processing rate is 1 Gbps, packet capture storage is 1 GB, and metadata indexing retention is 3 days.

## Metasploit

**Links:** [official website](https://www.metasploit.com/), [documentation](https://docs.rapid7.com/metasploit/)

The Metasploit Framework is a Ruby-based, modular penetration testing platform that provides a complete penetration testing environment and exploits development. It is a collection of commonly used tools, and it is used to write, test, and execute exploit code. The Metasploit Framework tools can be used to test security vulnerabilities, enumerate networks, execute attacks, and evade detection. It provides the command line interface named MSFconsole, for working with this framework. This framework allows manual exploitation and credentials brute-forcing.

The Metasploit Pro is the exploitation and vulnerability validation tool. This tool can divide the penetration testing workflow into manageable sections. The typical workflow steps are as following: create a project, get target data, view and manage host data, run a vulnerability scan, set up a listener, exploit known vulnerabilities, post-exploitation and collect evidence, clean up sessions, generate a report. Unlike the Metasploit Framework, the Metasploit Pro  provides a web interface, automated exploitation and credentials brute-forcing, baseline penetration testing reports, wizards for standard baseline audits, task chains for automated custom workflows, closed-Loop vulnerability validation to prioritize remediation, web app testing for OWASP Top 10 vulnerabilities, network discovery, integrations via Remote API, and more.

## nbtstat

**Links:** [Windows documentation page](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/nbtstat)

A nbtstat is a Windows command-line diagnostic tool that displays NBT (NetBIOS over TCP/IP) statistics. The other features include displaying NetBIOS name tables and the NetBIOS name cache, and refreshing of the NetBIOS name cache and the names.

## Nessus

**Links:** [official website](https://www.tenable.com/products/nessus)

A Nessus is a vulnerability assessment tool. It is a multiplatform tool that can be run on Windows, Linux and MacOC operating systems.

It can be deployed as:

* *Nessus Essentials* - free version of the Nessus tool,
* *Nessus Proffesional* - commercial version of the Nessus tool,
* *tenable.io* - commercial cloud tool with unlimited Nessus Scanners.

The commercial version of Nessus include except high-speed, in-depth assessments, also unlimited and configuration assessment, live results, and configurable reports.

The advantages of Nessus include:

* the industry's lowest false positive rate with six-sigma accuracy,
* the deepest and broadest vulnerability coverage in the industry,
* the #1 deployed solution for application vulnerability assessment.

## Netcat

**Links:** [documentation](https://nc110.sourceforge.io/), [product description](https://sectools.org/tool/netcat/)

A Netcat, also known as nc, is a utility that opens TCP or UDP connections and reads and writes the data. It supports inbound and outbound connections to or from any ports. It is designed as a Linux backend tool. This utility can be considered a powerful debugging and exploration tool since it can provide any network connection.

The other features of this tool include a full DNS forward/reverse checking, port-scanning, loose source-routing, slow-send mode, hex dump of transmitted and received data, and telnet-options responder. 

There are many tools similar to the Netcat, such as Ncat, Socat, OpenBSD's nc, Cryptcat, Netcat6, pnetcat, SBD, and GNU Netcat.

## NetDetector

**Links:** [official website](https://www.niksun.com/product.php?id=112), [datasheet](https://www.phoenixdatacom.com/wp-content/uploads/2015/09/NIKSUNDatasheet_NetDetector_pdl.pdf), [product description](https://www.phoenixdatacom.com/product/niksun-netdetector-packet-capture-network-security-forensics/)

A Niksun NetDetector is a packet capture and network security forensic tool. It is a proprietary network forensic tool, available in 4 iterations.

The NetDetector's variations are:

* *NetDetector* - full packet capture, application fingerprinting/reconstruction, IDS and anomaly detection,
* *NetDetectorLive* - NetDetector with real-time reconstruction, indexing and content alarming,
* *Virtual NetDetector/NetDetectorLive* -  cloud version of NetDetector/NetDetectorLive,
* *IntelliDefend* - NetDetector in a lightweight, notebook-sized device.


The NetDetector is a full-featured appliance for network security
monitoring. It is used to capture and analyze packets. It is also  possible to import and export data in many formats. It provides ad-hoc and scheduled reporting on multiple timescales.

The most important features of NetDetector include: dynamic application recognition and plug-ins, integrated anomaly and signature-based IDS, application and session reconstruction, and 100Gbps packet capture and analysis.

## NetFlow

**Links:** [product website (Cisco IOS NetFlow)](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-netflow/index.html), [white paper (Cisco IOS NetFlow)](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-netflow/prod_white_paper0900aecd80406232.pdf)

NetFlow is a protocol developed by Cisco. It is a part of the Cisco IOS Software. It provides the information about who, what, when, where, and how network traffic is flowing. It exports the data to NetFlow collectors that create reports.

It provides information about network users and applications, peak usage times, and traffic routing. The latest version, NetFlow v9, is the basis of a new IETF standard, and it is a flexible and extensible method to record network performance data.

## NetFlow Configurator

**Links:** [official website](https://www.solarwinds.com/free-tools/netflow-configurator)

A NetFlow Configuration is a free version of the Solarwinds NetFlow Traffic Analyzer but with fewer functions. It can remotely activate NetFlow on network devices via SNMP. The key features include analyzing network performance, activating NetFlow, finding bandwidth hogs, bypassing the CLI with an intuitive GUI, setting up collectors for NetFlow data, specifying collector listening ports, and monitoring traffic data per interface.

## NetFlow Traffic Analyzer (NTA)

**Links:** [official website](https://www.solarwinds.com/netflow-traffic-analyzer)

A NetFlow Traffic Analyzer is a commercial network analyzer and 
bandwidth monitor. The other key features include application traffic alerting, VMware vSphere distributed switch support, performance analysis dashboard, and advanced application recognition. This tool is available for Windows systems (on-premise) or may be installed on VMware Virtual Machines and Microsoft Virtual Servers. The free 30 days trial version is also available.

## Netfox Detective

**Links:** [GitHub repository](github.com/nesfit/NetfoxDetective)

A Netfox Detective is an open-source Windows network forensic analysis tool that extracts the application content from the communication. This tool supports the following application protocols: BTC - Stratum, DNS, Facebook, FTP, Hangouts, HTTP, OSCAR - ICQ, IMAP, Lide.cz, Messenger, Minecrat, MQTT, POP3, RTP, SIP, SMTP, SPDY, Twitter, Webmails - various services, Xchat.cz, XMPP, YMSG. It can work with capture files; the live capture is not supported. The key features include multiple PCAPs support, large PCAPs support, advanced visualization, filters, and full-text search.

## NetIntercept

**Links:** [datasheet](https://www.neox-networks.com/downloads/NIKSUNDatasheet_NetIntercept.pdf)

A NetIntercept is a network tool with a focus on the data flows. It is similar to the open-source tool tcpflow. The NetIntercept is a commercial program created by Sandstorm Enterprises, acquired by NIKSUN company.

The NetIntercept is an IDS/IPS with forensics capability. It can detect and block attacks, restrict traffic by IP and port, utilize full packet-based evidence and deep packet inspection with intelligent threat response, and search records of blocked traffic. This tool provides a web-based interface.

## NetScanTools Basic and NetScanTools Pro

**Links:** [official website (NetScanTools Basic Edition)](https://www.netscantools.com/nstbasicmain.html), [official website (NetScanTools Pro)](https://www.netscantools.com/nstpromain.html)

A NetScanTools Basic Edition is a freeware set of essential network tools that includes DNS Tools (simple IP/hostname resolution, computer name, IP and DNSs), Ping, Graphical Ping, Ping Scanner, Traceroute, and Whois.

A NetScanTools Pro is a powerful commercial set of network tools that include many network tools and utilities. It covers the following category of tools:

* *Active Discovery and Diagnostic Tools* - to locate and test devices connected to the network (ARP Ping, DHCP Server Discovery, Email Validate, Finger, Network Routing Visualizer, OS Fingerprinting, Ping, Port Scanner, SMB Scanner, SSL Certificate Scanner, and others),
* *Passive Discovery Tools* - to find information from third parties or to monitor the activities of devices connected to the network (Connection Monitor, Network Connection Endpoints, Packet Capture, Passive Discovery, Real-Time Blacklist Check, Whois),
* *DNS Tools* - to help to find problems with DNS (Simple Query - IPv4/IPv6, Who Am I?, Flush Default DNS Cache, Edit DNS HOSTS File, Auth Serial Check, DNS Verify, IP Drilldown, SPF/Domain Keys, DNS List Speed Test, IP or Hostname to ASN, Get VOIP/Misc SRV Records, and others),
* *Local Computer and General Information Tools* - provide information about the local computer's network and also include general information tools (ARP Cache, Cache Forensics, IP to Country, IP/MAC Address Database, Launcher, Network Interfaces and Statistics, IPv6 Network Neighbors, TCP/UDP Service Lookup, and others)

## netstat

**Links:** [Linux man page](https://linux.die.net/man/8/netstat), [Windows documentation page](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat)

A netstat is a command line network tool available for Windows, Linux and other Unix systems. It provides the network statistics including network connections, routing tables, interface statistics, masquerade connections, and multicast memberships.

## NetStumbler

**Links:** [official website](http://www.stumbler.net/)

A NetStumbler is a network tool for detecting Wireless Local Area Networks (WLANs) using 802.11b, 802.11a, and 802.11g. The NetStumbler is developed for Windows systems. For Windows CE, there is available MiniStumbler.

The main features include: detecting networks that may cause interference, detecting unauthorized "rogue" APs, and finding locations with poor coverage.

## NetVCR

**Links:** [official website](https://www.niksun.com/product.php?id=110), [datasheet](https://www.niksun.com/c/1/ds/NIKSUNDatasheet_NetVCR.pdf)

A NetVCR is a part of the NetVCR Suite. It is a commercial network tool used to capture packets.

The NetVCR Suite include:

* *NetVCR* - full packet capture with stream-to-disk recording, real-time indexing and application analytics,
* *Virtual NetVCR* - cloud version of NetVCR,
* *IntelliNetVCR* - NetVCR in a lightweight, notebook-sized device,
* *NetVoice* - analyzing Voice over IP traffic,
* *NetTradeWatch* - analyzing financial transactions and associated market data feeds,
* *NetBlackBox Pro* - NetVCR-like full packet capture and archiving without the extensive metadata warehouse, providing a cost-effective, flexible solution for performance analysis and forensics.

Some benefits of the NetVCR include: proactive alerting, QoS management and reporting, diagnostics and troubleshooting, accounting, performance analysis, and application/services monitoring.

## NetWitness

**Links:** [official website (RSA Threat Detection and Response)](https://www.rsa.com/en-us/products/threat-detection-response)

A NetWitness was acquired by EMC company, and NetWitness products were integrated into EMC's RSA Security unit.

The RSA NetWitness Platform combines SIEM and threat defense solutions. It is a commercial network tool that collects and analyzes data across many capture points, computes on physical, virtual, or cloud platforms, and enriches this data with threat intelligence and business context.

## Network Flight Recorder (NFR)

**Links:** [GitHub repository](github.com/alphasoc/nfr)

A Network Flight Recorder is a lightweight application for processing network traffic. It uses the AlphaSOC Analytics Engine. It is an open-source tool and can be run on Linux systems, it can also be run as a service in Windows systems using NSSM.

The NFR can monitor and actively read log files from disk (log files by other applications like Bro/Zekk IDS, Microsoft DNS, Suricata DNS) or process events directly from the network (capture traffic data as a network sniffer). In addition to capturing the packets, it also provides in-depth analysis and alerting of the suspicious events, including identifying gaps in the security controls, highlighting targeted attacks and policy violations.

The data can be exported in JSON or CEF format or sent via Syslog. NFR provides a command-line interface with few predefined commands.

## Network Topology Mapper

**Links:** [official website](https://www.solarwinds.com/network-topology-mapper)

A Network Topology Mapper is a commercial network tool used to automatically plot the network. There is available 14\,days free trial version. The key features include automatic device discovery and mapping, building multiple maps from a single scan, exporting network diagrams to Visio, auto-detecting changes to network topology, performing multi-level network discovery, and addressing regulatory PCI compliance. This tool is available for Windows systems.

## NetworkMiner

**Links:** [official website](https://www.netresec.com/?page=Networkminer)

A NetworkMiner is an open-source network security tool. It can be run on Linux, Windows, FreeBSD, and MacOS systems. It can be deployed as a free edition NetworkMiner, or commercial edition NetworkMiner Professional.

The NetworkMiner can be run as a passive network sniffer, or it can parse and analyze already captured network traffic data in PCAP files. It can identify involved hosts, including detailed information like IP, MAC, Operating system, Sent/Received bytes, Open ports, Incoming/Outcoming traffic. It can also obtain files, images, and messages from the traffic. Moreover, it can parse credentials, sessions, DNS, parameters, keywords, and anomalies. Also, it provides filtering according to the selected criteria.

## NfDump

**Links:** [GitHub repository](https://github.com/phaag/nfdump)

A NfDump is an open-source toolset used for collecting and processing the network flow data (netflow v1, v5/v7, v9, IPFIX, and SFLOW). This tool provides the command line interface. The NfDump is used as a backend toolset for NfSen.

The NfDump contains the following tools:

* *nfcapd* - netflow collector daemon,
* *nfdump* - process collected netflow records,
* *nfanon* - anonymize netflow records,
* *nfexpire* - expire old netflow data,
* *nfreplay* - netflow replay,
* *nfpcapd* - pcap to netflow collector daemon,
* *sfcapd* - sflow collector daemon,
* *nfprofile* - netflow profiler for NfSen (reads data from nfcapd),
* *nftrack* - port tracking decoder for NfSen plugin PortTracker,
* *ft2nfdump* - flow-tools flow converter into nfdump format,
* *nfreader* - framework for reading nfdump files,
* *parse\_csv.pl* -Perl reader that reads nfdump csv output

## NfSen

**Links:** [official website](http://nfsen.sourceforge.net/)

A NfSen is an open-source web-based frontend of NfDump toolset. It provides the graphical interface. This tool is hosted by Sourceforge.

The main features of this tool include displaying the netflow data, navigating through the netflow data, processing netflow data within a specified time range, creating history, setting alerts, and writing own plugins.

## Ngrep

**Links:** [GitHub repository](https://github.com/jpr5/ngrep/)

A Ngrep is an open-source network tool that can be run on multiple platforms, including Linux, Windows, and MacOS. This tool searches and filters the network packets according to the specified patterns. It can work as a sniffer and monitor the network interfaces or read the packet data from the network capture file.

The features of the Ngrep include debugging plaintext protocol interactions, identifying and analyzing anomalous network communications, and storing, reading and reprocessing pcap dump files while looking for specific data patterns.

## Nikto

**Links:** [official website](https://cirt.net/Nikto2), [GitHub repository](https://github.com/sullo/nikto)

A Nikto is an open-source web server scanner for Linux systems.

It performs comprehensive tests against web servers for multiple items, including potentially dangerous files/programs, checks for outdated versions, version specific problems, and checks server configuration items.

The major features of Nikto include: SSL Support, Full HTTP proxy support, Identifies installed software, Replay saved positive requests, Enhanced false positive reduction, Guess credentials for authorization realms, Scan tuning to include or exclude entire classes of vulnerability checks, username enumeration, Template engine to easily customize reports, and more.

## Nmap

**Links:** [official website](https://nmap.org/)

A Nmap is an open-source network mapper used for network discovery and security auditing that works on a single host or large networks. This tool can also be useful during the network inventory, managing service upgrade schedules, and monitoring host or service uptime. It can provide information about the available hosts and services, operating system information (such as a version of the operating system), type of packet filters/firewalls, and more.

In addition to the command-line interface, this tool also provides a graphical user interface called Zenmap. This network tool can be run on multiple platforms, including Windows, Linux, and MacOS.

The other tools that are part of the Nmap include:

* *Ncat* - a flexible data transfer, redirection, and debugging tool,
* *Ndiff* - a utility for comparing scan results,
* *Nping* - a packet generation and response analysis tool

## nslookup

**Links:** [Linux man page](https://linux.die.net/man/1/nslookup), [Windows documentation page](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup)

A nslookup is command-line network tool that query Internet domain name servers. This tool is used for diagnosing DNS infrastructure. It can work in interactive or non-interactive mode. The interactive mode is used to look up more than one piece of data. The non-interactive mode is recommended for looking up only a single piece of data. It is available in multiple operating systems, inlcuding Windows, Linux, and MacOS.

## Ntop

**Links:** [official website](https://www.ntop.org/), [GitHub repository](https://github.com/ntop)

A Ntop is an open-source network traffic monitoring software that consists of many tools that can capture packets and record and analyze traffic.

The Ntop contains the following tools:

* *ntopng* - web-based traffic analyzer and flow collector,
* *nDPI* - Deep Packet Inspection framework,
* *nProbe* - NetFlow v5/v9/IPFIX probe with plugins support for L7,
* *PF\_RING* - packet capture,
* *n2disk* - network traffic recorder,
* *disk2n* - network traffic replayer.

## oftcat

**Links:** [GitHub repository](https://github.com/kiddinn/misc/blob/master/scripts/oftcat)

An oftcat is a simple Perl script that parses OFT (Oscar File Transfer) packages and saves the gained info into a specified file.

## OmniPeek

**Links:** [official website](https://www.liveaction.com/products/omnipeek-network-protocol-analyzer/)

An OmniPeek is a commercial network protocol analyzer with graphical user interface. It provides real-time deep packet analysis including layer 7 traffic. The other features include analyzing traffic from any remote network segment, monitoring voice and video over IP traffic in real time, capturing and analyzing 802.11n and 802.11ac wireless traffic from already deployed access points, integrated flow and packet-level analysis, expert analysis, and automatic alerts.

## P0f

**Links:** [official website](https://lcamtuf.coredump.cx/p0f3/#)

A P0f is a free network tool that identifies the players behind TCP/IP communications without interfering. It uses passive traffic fingerprinting mechanisms. 

Other capabilities include highly scalable and fast identification of the operating system and software, automated detection of connection sharing/NAT, load balancing, and application-level proxying setups. Moreover, it can measure the system uptime and network hookup, distance (including NAT or packet filters), user language preferences. 

This tool's typical uses include reconnaissance, network monitoring, detection of unauthorized network interconnects, and forensics.

## PADS

**Links:** [official website](http://passive.sourceforge.net/)

A PADS, Passive Asset Detection System, is a free portable lightweight signature-based detection engine that passively detects network assets. It listens to network traffic, attempts to identify the applications running on the network, and creates reports in the CSV format.

## PassiveDNS

**Links:** [GitHub repository](https://github.com/gamelinux/passivedns)

A PassiveDNS is an open-source network sniffer that collects DNS record passively. It can be used in Incident handling, Network Security Monitoring (NSM) and general digital forensics. This tool can read PCAP file or capture the traffic data from an interface. It also can export the DNS-server answers to a log file. The other features are IPv4 and IPv6 support, and it can parse DNS traffic over TCP or UDP. One of the typical use case is searching for domain or IP history when working on an incident.

## pcapcat

**Links:** [GitHub repository](https://github.com/kiddinn/misc/blob/master/scripts/pcapcat)

A pcapcat is a simple Perl script that reads PCAP files and prints the information about the connections. This tool also provides the ability to filter the data using the traditional pcap filters and stores the gained information into a file.

## PcapXray

**Links:** [GitHub repository](https://github.com/Srinivas11789/PcapXray)

A PcapXray is an open-source network tool that reads a PCAP file and visualizes the network in a network diagram. It displays hosts in the network, network traffic, highlight significant traffic and Tor traffic as well as potentially malicious traffic, including data involved in the communication.

## ping

**Links:** [Linux man page](https://linux.die.net/man/8/ping), [Windows documentation page](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ping)

A Ping is an command line network tool used for verifying IP-level connectivity to another TCP/IP computer. Is sends ICMP Echo request messages to network hosts. This command is available on multiple operating systems, including Windows, Linux and MacOS.

## Port Scanner

**Links:** [official website](https://www.solarwinds.com/free-tools/port-scanner)

A Port Scanner is a free network tool that scans available IP addresses and their corresponding TCP and UDP ports to identify network vulnerabilities. It provides lists of open, closed, and filtered ports for each scanned IP address. The other features include defining a DNS server, saving scan configurations, tracking user and endpoint device connection activity, and viewing and editing IANA port name definitions.

## PyFlag

**Links:** [official website](https://sourceforge.net/projects/pyflag/), [Google Code Archive](https://code.google.com/archive/p/pyflag/)

A PyFlag, Python implementation of FLAG (Forensic and Log Analysis GUI), is an open-source advanced forensic tool for analyzing log files and forensic investigation. This tool can process large PCAP files, analyze and extract the content of the communication. The PyFlag is able to recursively examine data at multiple levels and discover files encapsulated within other files. It also provides advanced reconstruction of web pages, and specific analysis for popular webmail sites.

The architecture consists of the following components: IO Source, File System Loader, VFS, Scanners, Database, and Web GUI.

The PyFlag is marked as deprecated and is no longer maintained according to the [Forensics Wiki](https://forensicswiki.xyz/wiki/index.php?title=PyFlag).

## Sebek

**Links:** [official website from web archive](https://web.archive.org/web/20190921171854/http://www.honeynet.org/project/sebek/), [project website from web archive](https://web.archive.org/web/20190304212247/http://projects.honeynet.org/sebek), [GitHub repository](https://github.com/honeynet/sebek)

A Sebek is an open-source data capture tool that works on the kernel level. It uses techniques similar to those used by rootkits. The aim is to capture an attacker's activities (keystrokes, file uploads, passwords) on a honeypot, without the attacker knowing it. This tool is available for Linux (2.4 and 2.6 kernels) and Windows systems.

This capture tool consists of two components:

* *a client* - runs on the honeypots, captures activities, and sends the data to the server,
* *the server* - runs on the Honeywall gateway (or independently), collects the data from the honeypots

## Security Event Manager (SEM)

**Links:** [official website](https://www.solarwinds.com/security-event-manager)

A Security Event Manager (SEM) is a commercial SIEM tool that provides security information and event management solution. The main features include centralized log collection and normalization, automated threat detection and response, integrated compliance reporting tools, an intuitive dashboard and user interface, and built-in file integrity monitoring. The free 30\,days trial version is also available. The SEM is based on a manager and agent system, where the manager is distributed as a virtual machine, and agents can be installed on multiple platforms including Linux, Windows, and MacOS.

## sFlow

**Links:** [official website](https://sflow.org/index.php)

A sFlow is a technology for monitoring network traffic data. The architecture consists of agents and collectors. It is an industry standard that provides a network-wide view of usage and active routes (measuring network traffic, collecting, storing, and analyzing traffic data).

## SilentRunner

**Links:** [product description (brochure)](https://silo.tips/download/silentrunner-brochure), [product website from web archive](https://web.archive.org/web/20111128113603/http://accessdata.com/products/cyber-security-incident-response/ad-silentrunner-sentinel)

A SilentRunner was a part of the AccessData Platform family of products. The SilentRunner Sentinel worked as visibility into network traffic.

The features of SilentRunner Sentinel include capturing real-time network data in all OSI layers (including VoIP), visualization of the network activity, audit logs, and alerts, determining the root cause of a security breach, building integrated maps, conducting post-event analysis, and reconstructing events.

## SiLK

**Links:** [official website](https://tools.netsa.cert.org/silk/)

A SiLK is a set of traffic analysis tools. Its components are open-source. It is designed to analyze traffic. The supported platforms include Linux, Solaris, OpenBSD, Mac OS X, and Cygwin.

The SiLK tool suite supports the efficient collection, storage, and analysis of network flow data, enabling network security analysts to rapidly query large historical traffic data sets. 

The installation consists of the following categories of applications:

* *the packing system* - collecting flow data (IPFIX, NetFlow v9, or NetFlow v5) and converting them into a more space efficient format, recording the packed records into binary flat files,
* *the analysis suite* - tools for reading the created flat files that can perform various query operations, such as per-record filtering or statistical analysis of groups of records.

## Skyhook

**Links:** [official website](https://www.skyhook.com/), [documentation from web archive](https://web.archive.org/web/20080604163052/http://www.skyhookwireless.com/howitworks/)

Skyhook is a company that develops geo-positioning software solutions. They focus on location positioning, context, and intelligence. 

One of the first products of this company was a Wi-Fi Positioning System (WPS). The WPS was a software location solution for determining the location of devices using land-based Wi-Fi access points.

Now, Skyhook's products include 

* *Skyhook Precision Location* - The fast, accurate location for any app or device, available for Linux, Windows, MacOS, and Android systems,
* *Skyhook Context SDK* - client-side geofences, comprehensive DB locations, and insight into offline user behavior, available for iOS and Android systems,
* *Skyhook Geospatial Insights* - insight into the localization of mobile consumer behavior, available for iOS, Android, and Web systems

## SmartWhois

**Links:** [official website](https://www.tamos.com/products/smartwhois/)

A SmartWhois is a commercial network information utility used to look up information about the IP address, hostname, or domain. The SmartWhois can also provide information about the country, state or province, city, name of the network provider, administrator, and technical support contact information. This tool is available for Windows systems.

## smtpdump

**Links:** [product code](http://malphx.free.fr/dotclear/public/nfpc2/smtpdump)

A smtpdump is a free network tool that extracts SMTP information from PCAP files. It was written for the Network Forensic Puzzle \#2 Contest.

## snoop

**Links:** [GitHub repository](https://github.com/snoopwpf/snoopwpf)

A Snoop is an open-source network tool for Windows systems. It is a WPF spying utility used to browse the visual tree of a running application and change properties, view triggers, or set breakpoints on property changes.

## snort

**Links:** [official website](https://www.snort.org/)

A snort is an open-source IPS tool that uses rules for defining malicious network activity. It finds packets that match against rules and generates alerts. It is a multiplatform tool available for Windows, Linux, and FreeBSD systems. The snort can be used as a packet sniffer, a packet logger, or a full-blown IPS system.

## softflowd

**Links:** [Google Code Archive](https://code.google.com/archive/p/softflowd/)

A Softflowd is a software NetFlow probe. It is a flow-based network traffic analyzer that semi-statefully tracks traffic flows. The Softflowd can read a capture file or listen on the specified interface. The flows can be summarised by softflowd or reported via NetFlow. It is designed for minimal CPU load on busy networks.

## SplitCap

**Links:** [official website](https://www.netresec.com/?page=SplitCap)

A SplitCap is a free tool used for splitting capture files. There can be specified criteria for splitting the PCAPs - BSSID (WLAN BSSID), Flow (5-tuple), Host (IP address), Host Pair (IP pairs), MAC address, Session (bi-directional flow), Time, and Packets Count. This tool can be run Linux and Windows systems.

## SSLsplit

**Links:** [official website](https://www.roe.ch/SSLsplit)

An SSLsplit is an open-source tool used for man-in-the-middle attacks against SSL/TLS encrypted network connections. This tool is available for multiple platforms, including Linux, FreeBSD, OpenBSD, Debian, and MacOS systems. It supports plain TCP, plain SSL, HTTP and HTTPS connections over both IPv4 and IPv6. It also fully supports Server Name Indication (SNI) and can work with RSA, DSA and ECDSA keys and DHE and ECDHE cipher suites. There are also logging options that include traditional SSLsplit connect and content log files as well as PCAP files and mirroring decrypted traffic to a network interface. Certificates, master secrets, and local process information can also be logged.

## Stenographer

**Links:** [GitHub repository](https://github.com/google/stenographer)

A Stenographer is an open-source packet capture tool. It is designed to write packets to disk, store as much history as it can, and read a very small percentage of packets from disk based on analyst needs.

## Suricata

**Links:** [official website](https://suricata-ids.org/)

A Suricata is an open-source network threat detection engine that is capable of real time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM) and offline pcap processing. The Suricata uses rules and signature language with Lua scripting. It provides YAML and JSON output, and it can integrate with tools like existing SIEMs, Splunk, Logstash/Elasticsearch, Kibana. This tool is available for multiple platforms including Linux, Windows, and MacOS.

## TCPDstat

**Links:** [GitHub repository](https://github.com/netik/tcpdstat), [tcpdstat-uw from web archive](https://web.archive.org/web/20150808152314/https://staff.washington.edu/dittrich/talks/core02/tools/)

A tcpdstat is a Linux open-source tool that analyzes network traffic data files (dump files) and provides the statistics.

## tcpdump/libpcap

**Links:** [official website](https://www.tcpdump.org/)

A tcpdump and a libpcap are open-source network tools for Linux systems. The tcpdump is a command-line packet analyzer, and the libpcap is a portable C/C++ library for network traffic capture.

The tcpdump can capture, display and store network traffic data. It also can work with the already captured or real-time packets. Using flags and parameters when running the tcpdump, many function can be set, for example specifying read/write file, interface, and other functions defined in the manual page.

## TCPFlow

**Links:** [GitHub repository](https://github.com/simsong/tcpflow), [product description](https://calhoun.nps.edu/handle/10945/36026)

A TCPFlow is an open-source network tool similar to the commercial tool NetIntercept. This tool was developed by Jeremy Elson, today it is maintained by Simson Garfinkel. It can be run on Linux, Windows, and MacOS systems.

This tool aims to capture the network data, process them as TCP connections, store each flow into a separate file. Therefore, one typical TCP flow has two files, one for each direction. In addition to the live data capturing, the tcpflow can also process already captured data in capture files. Each created file contains source IP and port, and destination IP and port, in the filename. These created files after processing the packets, are used for later analysis. There are also many options that can be used when running the tcpflow, such as interpreting HTTP responses.

The tcpflow can be used to obtain HTTP session content, including web page reconstruction or malware extraction. Moreover, the tcpflow can create the output report in the DFXML format that contains detailed information, including the system information and every TCP flow information.

## TCPReplay

**Links:** [official website](http://tcpreplay.appneta.com/), [GitHub repository](https://github.com/appneta/tcpreplay)

A TCPReplay is a suite of tools for Unix systems for editing and replaying network traffic. This toolset works with the already captured network traffic data into capture files.

This suite contains the following tools: tcpreplay (replays pcap files), tcpreplay-edit (replays pcap files with option to modify packets), tcpliveplay (replay TCP pcap files directly to servers), tcpprep (pcap file pre-processor), tcprewrite (pcap file editor which rewrites packet headers), tcpcapinfo (raw pcap file decoder and debugger), and tcpbridge (bridge two network segments).

Other features of the TCPReplay include support for netmap, flow statistics and analysis, and support for both single and dual NIC modes for testing both sniffing and in-line devices.

## tcpslice

**Links:** [GitHub repository](https://github.com/the-tcpdump-group/tcpslice/)

A tcpslice is an open-source tool that extracts portions of packet trace files. It can concatenate multiple pcap files together or extract time slices from one or more pcap files. This tool was developed by "Lawrence Berkeley National Laboratory" and is now maintained by "The Tcpdump Group".

## TCPStat

**Links:** [official website](https://frenchfries.net/paul/tcpstat/)

A tcpstat is a Unix command-line tool that reports network interface statistics. The tcpstat can work with already captured traffic data in a dump file or monitor specific interfaces. This tool's statistics include bandwidth, number of packets, packets per second, average packet size, a standard deviation of packet size, and interface load.

## TCPTrace

**Links:** [official website from web archive](https://web.archive.org/web/20201124114030/http://www.tcptrace.org/), [GitHub repository](https://github.com/blitz/tcptrace)

A tcptrace is a Unix command-line tool that analyzes the TCP connections from dump files. This tool provides detailed information about TCP connections by sifting through dump files. It can work also on Windows and MacOS systems. The provided statistics include packet statistics, RTT statistics and CWND (Congestion Window) statistics.

## TCPXtract

**Links:** [official website](http://tcpxtract.sourceforge.net/)

A TCPXtract is an open-source network tool used to extract files from network traffic based on file signatures. This tool can be used against a live network (using the libpcap library) or a tcpdump formatted capture file.

## traceroute/tracert

**Links:** [Linux man page (traceroute)](https://linux.die.net/man/8/traceroute), [Windows documentation page (tracert)](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tracert)

A traceroute and a tracert are built-in monitoring and network diagnostic tools. The traceroute is a command for Unix and MacOS systems; the tracert is a command for Windows systems. Both commands work the same way. They print the route packets trace to network host using the ICMP messages and IP protocol's TTL.

## tshark

**Links:** [official website](https://www.wireshark.org/docs/man-pages/tshark.html)

A tshark is a network protocol analyzer. It is a part of the Wireshark tool and can be installed together with the Wireshark. Since Wireshark is a multiplatform tool, also tshark can be run on many operating systems, but Linux is preferred. The tshark provides a command-line interface.

It provides capturing packet data from a live network or reading packets from a previously saved capture file, either printing a decoded form of those packets to the standard output or writing the packets to a file. It also supports applying filters on captured data using the parameters.

## VisualRoute

**Links:** [official website](http://www.visualroute.com/)

A VisualRoute a network tool that offers a wide variety of network features. It is available for Windows and MacOS systems in Full or Lite version.

The features include continuous trace routing, reverse tracing, response time graphing, port probing, network scanning, trace route history, side by side trace route comparison, route analysis (NetVu), custom maps, remote access server, and save traceroutes as text, image or HTML. Extra features include Whois lookups, IP Locations, traceroute tests from Visualware servers, and IPv6 compatibility.

## Web Historian

**Links:** [official website](https://www.webhistorian.org/)

A Web Historian is an extension for the Google Chrome browser. It is used to visualize the web browsing history. It can visualize visited websites, searched items, network, time heatmap, and data table. It also provides a comparison to last week's statistics. This tool is available in the Educational and Community edition.

## WebScarab

**Links:** [official website (wiki OWASP WebScarab Project)](https://wiki.owasp.org/index.php/Category:OWASP_WebScarab_Project)

A WebScarab is a framework that is used to analyze applications using HTTP/HTTPS protocols. This tool is available for Windows and Linux systems.

The WebScarab provides several modes and plugins. It is mainly used as a proxy intercepting the HTTP and HTTPS communications, allowing an investigator to review and edit requests and responses. Other features include: reviewing the conversations, a bandwidth simulator, a parameter fuzzer, searching, BeanShell, sessionID analysis, and others.

## whois

**Links:** [Linux man page](https://www.commandlinux.com/man-page/man1/whois.1.html), [Windows documentation page](https://docs.microsoft.com/en-us/sysinternals/downloads/whois)

A whois is a command for performing the registration record for specified domain name or IP address. It is available in many operating systems, including Linux and Windows. It searches for an object in a [RFC 3912](https://tools.ietf.org/html/rfc3912) database.

## Wikto

**Links:** [GitHub repository](https://github.com/sensepost/wikto), [documentation](https://raw.githubusercontent.com/sensepost/wikto/master/Documentation/using_wikto.pdf)

A Wikto is an Nikto version for Windows platform with some additional features. It is a web server scanner. Some extra features include: fuzzy logic error code checking, a back-end miner, Google assisted directory mining, and real time HTTP request/response monitoring.

The Wikto provides graphical user interface. For full instalation, there is needed also [WinHTTrack](http://www.httrack.com/) and [HTTprint](http://www.net-square.com/).

## windump/WinPcap

**Links:** [official website (windump)](https://www.winpcap.org/windump/), [official website (WinPcap)](https://www.winpcap.org/)

A Windump is a free command-line network analyzer for Windows systems. This tool can be understood as an Windows version of the tcpdump. The Windump is used to capture, analyze, and export the network traffic data.

A WinPcap is an industry-standard Windows packet capture library. It allows applications to capture and transmit network packets. It can be understood as an Windows version of the libpcap. This library is used in many network tools, including Windump, Wireshark, Nmap, Snort, and ntop.

## Wireless Network Watcher

**Links:** [official website](https://www.nirsoft.net/utils/wireless_network_watcher.html)

A Wireless Network Watcher is a freeware utility that scans currently connected wireless network and displays the currently connected devices. This tool can be run on Windows systems. It provides the basic information of the connected devices, such as IP address, MAC address, computer name, and network card manufacturer.

## Xplico

**Links:** [official website](https://www.xplico.org/)

An Xplico is an open-source network forensic analysis tool that supports many protocols, including HTTP, SIP, IMAP, POP, SMTP, TCP, UDP, IPv6, Facebook, MSN, RTP, IRC, and Paltalk. This tool aims to gather application information from captured network traffic data, such as emails, HTTP content, VOIP calls, FTP, and others. It is not a network protocol analyzer.

It allows concurrent access by multiple users where one user can manage one or more cases. It provides a web user interface and can also be used as a cloud network forensic tool. Other features include multithreading, real-time elaboration, reverse DNS lookup, IPv4 and IPv6 support, and modularity.

## YAF

**Links:** [official website](https://tools.netsa.cert.org/yaf/)

A YAF, Yet Another Flowmeter, is an open-source flow sensor developed for Linux systems. It processes packet data, aggregates packets into flows, and export the information in IPFIX format. The YAF can work with dump files and also with the live captures from the interface.

In addition to yaf itself, the YAF toolchain also includes other tools, such us yafscii (printing in ASCII format), yafMeta2Pcap (PCAP metadata file parser and PCAP file creator), getFlowKeyHash (flow key calculator),
airdaemon (run as a daemon process), filedaemon (poll a directory and move files), and yafzcbalance (load balance from zc interfaces).

## Yersinia

**Links:** [GitHub repository](https://github.com/tomac/yersinia)

A Yersinia is an open-source framework for performing attacks on the data link layer including attacks on STP and CDP network protocols. It can be run on Linux systems.