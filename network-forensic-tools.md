## Network forensic tools

It is useful to have an overview of tools that can be used in network forensics with its basic description. The overview of available tools helps to choose the suitable tool that can assist in obtaining the information, collecting and analyzing the evidence, or creating the reports.

This website describes some network tools that can be used during network forensics. This overview includes both commercial and free to use tools. Some older tools are also included.
### Acunetix Web Vulnerability Scanner 

#### Links: [official website](https://www.acunetix.com/)

An Acunetix is a complete web application security testing solution that includes a web vulnerability scanner. It is a commercial tool and the pricing is based on the number of scanned websites. The Acunetix can be used both standalone and as part of complex environments. This product offers built-in vulnerability assessment, vulnerability management, and integration with software development tools. 

It can be deployed locally on Linux, Mac OS, and Microsoft Windows operating systems. In addition to the locally deployed product, the cloud version is also supported. 

### Aircrack-ng

#### Links: [official website](https://www.aircrack-ng.org/)

An Aircrack-ng is an open-source that was started in 2006 and is still developing. It is a suite of tools to assess WiFi network security. The Aircrack-ng can run on Windows and Linux machines. It also works on OS X, FreeBSD, OpenBSD, NetBSD, Solaris and eComStation 2.

There are four areas of WiFi security, the aircrack-ng focuses on:

* *Monitoring* - packet capture and data export for further analysis,
* *Attacking* - replay attacks, deauthentication, fake AP and others via packet injection,
* *Testing* - checking WiFi cards and driver capabilities (capture and injection),
* *Cracking* - WEP and WPA PSK.

The Aircrack-ng suite consists of the following tools - airbase-ng, aircrack-ng, airdecap-ng, airdecloak-ng, airdriver-ng, airdrop-ng, aireplay-ng, airgraph-ng, airmon-ng, airodump-ng, airolib-ng, airserv-ng, airtun-ng, besside-ng, dcrack, easside-ng, packetforge-ng, tkiptun-ng, and wesside-ng. The other tools include WZCook, ivstools, Versuck-ng, buddy-ng, makeivs-ng, and kstats.

### AirPcap/Riverbed AirPcap

#### Links: [official website](https://support.riverbed.com/content/support/software/steelcentral-npm/airpcap.html)

An Riverbed AirPcap, formely AirPcap, is a USB-based adapter that captures 802.11 wireless traffic. The captured data can be analysed by other analysis tools like Wireshark. The only supported platform for AirPcap is Windows.

The AirPcap Product Family contains products like AirPcap
Classic, AirPcap Tx, and AirPcap Nx. All these products can capture full 802.11 frames, are fully integrated with Wireshark, have open API, support multi-channel monitoring (with two or more adapters), and have USB dongle form. Packet transmission is available only on AirPcap Tx and AirPcap Nx. Frequency bands for AirPcap Classic and AirPcap Tx are 2.4 GHz (b/g), for AirPcap Nx 2.4 and 5 Ghz (a/b/g/n).

### Angry IP Scanner

#### Links: [official website](https://angryip.org/), [documentation](https://angryip.org/documentation/)

An Angry IP Scanner, also known as ipscan, is free and open-source network scanner. The aim of this tool is to scan IP addresses and ports, the results can be saved in many supported formats including CSV, TXT, XML or IP-Port list. It also support many plugins that can provide the user with the detailed information about scanned nodes like hostname, MAC address, or NetBIOS information. Other features include favorite IP address ranges, web server detection, customizable openers and so on

This network tool can be run on many platforms including Linux, Windows, and Mac OS X.

The advantages of the Angry IP Scanner include user-friendly interface, it is a very fast IP address and port scanner, it doesn't require any installation, and it uses multithreaded approach for increasing the scanning speed

### Argus

#### Links: [official website](openargus.org)

An Argus is the network flow system, developed by Carter Bullard in the early 1980's at Georgia Tech. The Argus Project is an open source project focused on proof of concept demonstrations of all aspects of large scale network awareness derived from network flow data. It is a real time flow monitor that is designed to perform comprehensive data network traffic auditing.

The Argus's main goal is to process captured packets or on the wire into the network flow data. It deals with the following issues of network flow data: scale, performance, applicability, privacy, and utility.

The Argus system consists of two parts:

* *argus* - a packet processing network flow sensor that generates Argus data,
* *argus-clients* - a collection of argus data processing programs.

The Argus Project efforts include: data generation, transport, collection, storage, analytics, and various metadata enhancements. 

The Argus is multi-platformed tools, it supports more than 24 platforms. The argus-clients focuses on data processing including data distribution, collection, filtering, aggregation, binning, minimization, privacy, metadata enhancement, geolocation, net-spatial location, compression, anonymization, graphing, databases, analytics, storage, and error correction.

### ARP

#### Links: [Linux man page](https://linux.die.net/man/8/arp), [Windows documentation page](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/arp)

An arp is a command-line network tool that is used to display and modify the ARP cache. This command is available for many platforms, including Linux, Windows, and MacOS systems. The main features include displaying ARP cache for single interface or all interfaces, deleting and adding an address mappings.

### Bless

#### Links: [GitHub repository](https://github.com/afrantzis/bless)

A Bless is an open-source binary HEX editor.

The main target platform for this tool is GNU/Linux. However, since all used libraries are cross-platform, the Bless is be able to run also on other platforms like BSD, Solaris, and Win32.

Some of the main features include:

* efficient editing of large data files,
* raw disk editing,
* mmultilevel undo - redo operations, fast find and replace operations, multi-threaded search and save operations,
* conversion table,
* export to text and html (others with plugins),
* extensibility with plugins.


### Bricata

#### Links: [official website](https://bricata.com/)

A Bricate is a commercial end-to-end network detection and response platform. It fuses signature inspection, stateful anomaly detection, and machine learning-powered malware conviction. It provides the real-time detection, response, hunting and defending against threats.

### Bro/Zeek

#### Links: [official website](https://zeek.org/), [documentation](https://docs.zeek.org/en/current/intro/index.html), [GitHub repository](https://github.com/zeek/zeek)

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


### CapAnalysis

#### Links: [official website](https://www.capanalysis.net/ca/)

A CapAnalysis is an open-source web-based capture file viewer that can work with more than one PCAP file. It performs indexing of data set of PCAP files and visualizes their contents in many forms - flows, statistics, source IPs, destination IPs, per hour statistics, Geo map, protocols, and timeline. The data or flows can also be filtered according to the IP, port, protocol, country, data volume, or date. This tool is available for Linux systems, like Debian or Ubuntu.

### CapLoader

#### Links: [official website](https://www.netresec.com/?page=CapLoader)

A CapLoader is a Window-based commercial tool that can handle large amounts of captured network traffic. It performs indexing of capture files and visualizes their contents as a list of TCP and UDP flows. It provides filtering of the packets and exporting packets/flows into the packet analyzer tool.

In addition to the professional edition, the 30\,days trial is also available. This trial version can handle 500 GB of captured data, supports pcapng and IPv6, can filter keywords and provides keywords string search. Other features of the trial version include flow transcript view, DNS parser, initial RTT calculation, network packet carving, input filter (BPF), display filter (BPF), hide flows in GUI, and service regularity/period detection. The professional version does not have a limit for PCAP files, and in addition to the features of the trial edition, it provides Alexa and Cisco Umbrella top 1M lookup, port independent
protocol identification (PIPI), OS fingerprinting, Geo-IP localization, ASN lookup, regular expression (regex) search, select flows from the log file or PCAP file, and Wireshark style Coloring.

### Carnivore

#### Links: [Open Carnivore article from web archive](https://web.archive.org/web/20141110081046/http://opencarnivore.org/), [Independent Review of the Carnivore System](https://epic.org/privacy/carnivore/carniv_final.pdf)

A Carnivore, also known as DCS1000, is an FBI software-based tool used to examine all IP packets on an Ethernet and record only those packets or packet segments that meet very specific parameters. Therefore this tool can be classified as a packet sniffer.

This tool can by installed by properly authorized FBI agents on a particular Internet Service Provider’s (ISP) network. This software system is used together with a tap on the ISP’s network. The aim is to intercept, filter, seize and decipher digital communications on the Internet.

This tool is not available for download.

### Check Point IPS-1/IPS

#### Links: [official website](https://www.checkpoint.com/products/intrusion-prevention-system-ips/), [IPS-1 Sensor Administration Guide](http://supportcontent.checkpoint.com/documentation_download?ID=10505), [The Check Point IPS Solution Administration Guide](https://sc1.checkpoint.com/documents/R76/CP_R76_IPS_AdminGuide/12742.htm)

A Check Point IPS-1 is an IPS that uses IPS-1 Sensors that can be placed on the network perimeter or at any location of internal network. 

The advantages of IPS-1 may include:

* Unified security management,
* Mission-critical protection against known and unknown attacks, 
* Granular forensic analysis,
* Flexible deployment,
* Confidence Indexing.


The Check Point IPS is available in two deployment methods: IPS Software Blade, and IPS-1 Sensor. 

The Check Point IPS is part of the Check Point Next Generation Firewall. It is a commercial IPS that detect or prevent attempts to exploit weaknesses in vulnerable systems or applications.

### chkrootkit

#### Links: [official website](http://www.chkrootkit.org/)

A chkrootkit is a free tool that locally checks for signs of a rootkit. This is a multiplatform tool that can be run on Linux, Windows, MacOS, Solaris, or BSD systems.

### Cisco FireSIGHT System
### Corero Network Security
### DeepSee
### dig
### DoHlyzer
### Dshell
### dumpcap
### E-detective
### EmailTrackerPro
### Enterasys IPS
### EtherApe
### Ethereal/Wireshark
### findject.py
### findsmtpinfo.py
### flow-tools
### FlowTraq
### Forensics Investigation Toolkit (FIT)
### Gnetcast (GNU Netcat)
### Haka
### HoneyBadger
### HP TrippingPoint IPS
### IBM Security NIPS
### ifconfig
### Index.dat analyzer
### InfiniStream (nGeniusONE)
### IP Address Tracker and IP Address Manager
### IPFIX
### IPTraf
### Iris
### KisMAC
### Kismet
### Log Analyzer
### LogRhythm NetMon and LogRhythm NetMon Freemium
### Metasploit
### nbtstat
### Nessus
### Netcat
### NetDetector
### NetFlow
### NetFlow Configurator
### NetFlow Traffic Analyzer (NTA)
### Netfox Detective
### NetIntercept
### NetScanTools Basic and NetScanTools Pro
### netstat
### NetStumbler
### NetVCR
### NetWitness
### Network Flight Recorder (NFR)
### Network Topology Mapper
### NetworkMiner
### NfDump
### NfSen
### Ngrep
### Nikto
### Nmap
### nslookup
### Ntop
### oftcat
### OmniPeek
### P0f
### PADS
### PassiveDNS
### pcapcat
### PcapXray
### ping
### Port Scanner
### PyFlag
### Sebek
### Security Event Manager (SEM)
### sFlow
### SilentRunner
### SiLK
### Skyhook
### SmartWhois
### smtpdump
### snoop
### snort
### softflowd
### SplitCap
### SSLsplit
### Stenographer
### Suricata
### TCPDstat
### tcpdump/libpcap
### TCPFlow
### TCPReplay
### tcpslice
### TCPStat
### TCPTrace
### TCPXtract
### traceroute/tracert
### tshark
### VisualRoute
### Web Historian
### WebScarab
### whois
### Wikto
### windump/WinPcap
### Wireless Network Watcher
### Xplico
### YAF
### Yersinia
