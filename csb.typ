#set page(margin: 1.5cm)
#set text(
  font: "Liberation Serif",
  size: 11pt,
)

#let definitions = table.with(columns : (auto, 1fr))

#align(center, text(13pt)[
  #heading[CSB Notes]
])

#show: rest => columns(2, rest)

== The CIA Triad
#definitions(
  [Confidentiality], [Information cannot be viewed by unintended recipients],
  [Integrity], [Information cannot be modified or tampered with],
  [Availability], [Authorized users won't be denied service]
)

== The AAA Triad
*Authentication:* Who are you? \
- Something you are (Biometrics and behaviours)
- Something you have (Keys)
- Something you know (Passwords)

*Authorisation:* What can you do? \
Users should not have access to private information that isn't relevant to them

*Accountability:* Who did what? \
Ensure any action done by any user is logged and traceable

== Types of attack
*Passive Attacks* \
Gathering data via monitoring transmissions
- Release of message contents
- Traffic analysis

*Active Attacks* \
Involves some modification of an existing data stream or creation of a new fake stream
#definitions(
  [Masquerade],[Pretending to be someone else],
  [Replay],[Caputing a legitimate transmission and copying it],
  [Modification],[Altering a legitimate stream],
  [Denial of Serice],[Inhibiting ability to communicate]
)

== Threats
*Threats to Confidentiality:*
- Snooping
- Traffic Analysis

*Threats to Integrity:*
- Modification
- Masquerading
- Replaying
- Repudiation

*Threats to Availability:*
- Denial of Service

#colbreak()

== Nonrepudiation:
- Prevents either sender or reciever from denying a transmitted message
- Reciever can verify the sender of a message
- Sender can verify the reciever of a message

== Message Authentication Code (MAC):
- Takes a secret key and a data block as input
- Produces a hash value (MAC) with is associated with the message
- If the integrity of the message needs to be checked, it can be re-hashed with the MAC function and compared with the attached MAC
An attacker who alters the message won't know the secret key used in the MAC function, and therefore cannot spoof a valid message

== Security definitions
*Unconditionally secure:* \
Encryption is secure because not enough information is given to decrypt it. (e.g. Vernam/Lorenz)

*Computationally secure:* \
- The cost of breaking the cipher exceeds the value of the encrypted information
- The time required to break the cipher exceeds the useful lifetime of the information

== History
*Data Encryption Standard:*
- Issued in 1977 by the National Bureau of Standards (now NIST)
- Most widely used encryption scheme until AES in 2001
- Algorithm itself referred to as Data Encryption Algorithm (DEA)
- Encrypts 64-bit blocks with a 56-bit key (symmetric)

*Morris Worm:*
- The first computer worm
- Before any real information/network security existed
- Duplicated itself 14% of the time even if the computer was already infected
- Result similar to that of a fork bomb

*The brain:*
- The first computer virus
- No serious malicious intent
- Overwrote first sector of boot sector with message
- "Beware of this virus... Contact us for vaccination..."

#colbreak()

== Networking
*Network structure:*
#definitions(
  [Circuit switching],[Dedicated circuit per call used by all data],
  [Packet switching],[Data sent in discrete packets, each with a path]
)

*Multiplexing:*
#definitions(
  [FDM],[Each user gets a fixed channel to communicate on],
  [TDM],[Each user gets allotted time slots during which they can communicate]
)

*OSI model:*
#table(columns: (auto, auto, 1fr),
  [*Protocol #linebreak() Data Unit*],[*Layer*],[*Responsibility*],
  [Data],[Application],[Network Process to Application],
  [Data],[Presentation],[ Data representation and encryption],
  [Data],[Session],[Inter-host communication],
  [Segments],[Transport],[End-to-End connections and Reliability],
  [Packets],[Network],[Path Determination and IP (Logical addressing)],
  [Frames],[Data Link],[MAC and LLC (Physical addressing)],
  [Bits],[Physical],[Media, Signal and Binary Transmission]
)

*Frame*
- A chunk of data created by network communication hardware such as Network Interface Cards and router interfaces
- Frames contain frame delimiters, hardware addresses, and data encapsulated from higher layer protocols

*Packets*
- Typically used to refer to chunks of data created by software
- Internet Protocol is often described as transmitting packets
- Packets contain logical addressing information such as IP addresses and data encapsulated from higher layer protocols

#colbreak()

== Protocols
*Application:*
- Post-Office Protocol (POP3)
- Simple Mail Transfer Protocol (SMTP)
- Domain Network System (DNS)
- File Transfer Protocol (FTP)
- Telnet

*Presentation:*
- Telnet (In slides but Google doesn't agree???)
- Network Data Representation (NDR)
- Lightweight Presentation Protocol (LPP)

*Session:*
- NetBIOS

*Transport:*
- Transmission Control Protocol (TCP)
- User Datagram Protocol (UDP)

*Network:*
- Internet Protocol (IP)
- Address Resolution Protocol (ARP)
- Internet Control Message Protocol (ICMP)

*Data link:*
- Serial Line Internet Protocol (SLIP)
- Point-to-Point Protocol (PPP)

*Physical:*
- IEEE 1394
- Digital Subscriber Line (DSL)
- Integrated Services Digital Network (ISDN)

== Network Attacks
*Categories:*
- Intrusion
- Blocking
- Malware

== Attacks on DNS
*Weakness of DNS:*
- TCP/UDP on port 53 (mostly UDP)
- Unencrypted
- Easily monitored
- Easily redirected
- Can be blocked
- Can be forged (if DNSSEC not used)

*Threats to DNS:*
- Corrupted host platforms
- Wireline and middleware inspection and interception
- Resolvers that leak queries
- Servers that leak queries

#colbreak()

== Attacks on DNS (continued)
*DNS Amplification Attack:*
+ Attacker spoofs a victim's IP address
+ Attacker requests large amounts of data from DNS servers
+ DNS servers send the requested data to the victim's IP
+ Victim essentially recieves a DDoS from the DNS servers

*DNS-over-TLS (DoT)*
- Released in 2016, first established DNS encryption solution
- Uses secure TLS channel on port 853 instead of common port 53
- Prevents attackers seeing or manipulating DNS requests

*DNS-over-HTTPS (DoH)*
- Introduced in 2018
- Uses TLS, like DoT, but does so via HTTPS with port 443

== Attacks on HTTP
*HTTP Session Hijacking / Cookie Stealing:*
+ Attacker injects script onto server
+ Victim authenticates on server
+ Victim's browser sends the session cookie to the attacker
+ Attacker can hijack the user's session

*Session Side Jacking:*
+ Attacker sniffs packets on local network (often unsecured hotspots)
+ If a session isn't entirely encrypted with SSL/TLS, a victim's session key might be contained within packets
+ The attacker can use the session key to hijack the session and impersonate the victim

*Solution:* Use HTTPS

== Attacks on TCP
*TCP Handshake:*
#definitions(
  [SYN],[Client $->$ Server],
  [SYN-ACK],[Client $<-$ Server],
  [ACK],[Client $->$ Server]
)
It's very difficult to intercept a TCP connection that's already established

#colbreak()

*TCP Session Hijacking:* \
Possible when an attacker is on the same network segment as the
target machine.
- Attacker can sniff all back/forth tcp packets and know the seq/ack numbers.
- Attacker can inject a packet with the correct seq/ack numbers with the spoofed IP address.
IP spoofing needs low-level packet programming, OS-based socket programming cannot be used!

*SYN Flooding Attack:* \
An attacker sends a large number of SYN requests to a target's system
- Target uses too much memory and CPU resources to process these fake connection requests
- Target's bandwidth is overwhelmed
Usually SYN flood packets use spoofed source IPs
- No TCP connection is set up (unlike TCP hijacking)
- Hides the attacking source
- Make it difficult for the target to decide which TCP SYNs are malicious and which are from legitimate users

*Potential Solutions for TCP:*
#definitions(
  [Ingress Filtering],[Drop all packets that aren't from expected destination],
  [uRPF Checks],[Only accept packets from interface if forwarding table entry for source IP address matches ingress interface (only works on symmetric routing)]
)

*SYN Flood Defence: SYN Cookie*
- Client sends SYN to server
- Server responds with SYN-ACK cookie
- Honest client responds with ACK
- Server checks response
- If matches SYN-ACK, establishes connection

== IP Spoofing
+ In the most basic IP spoofing attack, the hacker intercepts the TCP handshake before the source manages to send its SYN-ACK message.
+ The hacker sends a fake confirmation including their device address (MAC address) and a spoofed IP address of the original sender.
+ Now the receiver thinks that the connection was established with the original sender, but they're actually communicating with a spoofed IP.
IP address spoofing is most often
used to bypass basic security
measures such as firewalls that
rely on blacklisting.

#colbreak()

== IP Spoofing (continued)
*Denial of service* \
An attacker can send out millions of requests for files with a spoofed IP addresses, causing all of the responses to be sent to the victim's device.

*Man-in-the-middle attacks* \
If you're browsing an insecure HTTP address, an attacker can use IP spoofing to pretend they're both you and the service you're speaking to, thereby fooling both parties and gaining access to your communications.

== Attacks on ARP
*Address Resolution Protocol (ARP):*
- Each IP node (Host, Router) on LAN has an ARP table
- The ARP table contains mappings from IP to MAC \<IP address; MAC address; TTL>
- TTL = Time To Live: Time after which the mapping will be forgotten
- Works by broadcasting requests and caching responses

*ARP Spoofing:*
- ARP table is updated whenever a response is recieved
- Requests are not tracked
- ARP announcements are not authenticated
- A rogue machine can use this to spoof other machines

*ARP Spoofing Countermeasures:*
- Using static entries (hard to manage)
- Check for multiple occurences of the same MAC
- Software detection solutions (Anti-arpspoof, Xarp, Arpwatch)

== MITM Attacks
- ARP cache poisoning
- DNS spoofing
- IP spoofing
- Rogue WiFi access point
- SSL spoofing

== Radio Jamming Attack
By creating a noisy radio signal, we can cause enough interference to disrupt legitimate communication.

== Common types of DDoS attack:
- Application layer attacks (generate huge amounts of HTTP requests)
- Protocol attacks (Network/Transport Layer, e.g. SYN flooding)
- Volumetric attacks (e.g. DNS Amplification)

#colbreak()

== SQL Injection
Used to manipulate operations on databases, with the eventual goal of complete control over it.

== Cross-site scripting (XSS)
- Attacker injects malicious scripts into web applications
- Script will run on victim's devices when they use the app
- Can be used for session stealing

== Firewalls
- Filters traffic between a protected network and the outside
- Usually runs on a dedicated device, as performance is critical
- Usually runs on a minimal and proprietary OS to reduce attack sites
- Provides a focal point for monitoring
- Provides a central point for access control
- Limits the potential damage from a network security issue
- Doesn't protect against malicious insiders
- Doesn't protect connections that do go through
- Doesn't completely protect against new threats
- Doesn't protect against viruses, trojans, etc.

*Generic Techniques for Enforcing Policy:*
- Service Control: Determine the types of Internet services that can be accessed
- Direction Control: Determine the direction in which particular service requests are allowed
- User Control: Controls access to a service according to which user is attempting to access it.

*Types of Firewall:*
- Packet Filtering Firewall (Works at Network layer, IP)
- Circuit-level Gateway (Works at Transport layer, TCP)
- Stateful Inspection Firewall
- Application Level Gateway (Works at higher layers)

*Packet Filtering:*
- Simple and effective, uses packet addresses and transport protocol type to determine policy
- Works at most up to Transport layer, but on packet level
- Stateless
- Fast processing
- Lack of upper-layer functionality
- Doesn't supported advanced user authentication schemes
- Cannot block specific application commands. All-or-nothing

#colbreak()

== Firewalls (continued)
*Application-level Gateway (AKA Application Proxy):*
- Acts as a relay for Application-level traffic
- Tends to be more secure than packet filters
- Large processing overhead as all traffic must be forwarded

*Stateful Inspection Firewall:*
- Maintains state from one packet to another in the input stream
- Good at detecting attacks split across muliple packets

*Circuit-level Gateway (AKA Circuit-level proxy):*
- Can be stand-alone, or can be performed by an application-level gateway for specific applications
- Does not permit end-to-end TCP connections
- Traffic will appear as if it's coming from the gateway itself

*Personal Firewalls:*
- Useful to compensate for lack of regular firewall
- Can generate logs of accesses

== Intrusion Detection System (IDS)
- Typically a dedicated device on a system that monitors for malicious or suspicious events
- Monitors user and system activiy
- Audits system config for vulnerabilities and misconfigurations
- Assessing integrity of critical systems and data
- Recognizing known attack patterns in system activity
- Installs and operates traps to record information about intruders

*Signature-Based Intrusion Detection:*
- Performs simple pattern-matching corresponding to known attacks, such as lots of incoming TCP SYN packets on many ports
- Cannot detect attack patterns that aren't yet part of their attack pattern database
- Attacks will try to modify basic attacks to not match common attack signatures
- Often uses lots of statistical analysis

*Heuristic Intrusion Detection:*
- Instead of looking for specific patterns, looks for odd behaviour
- e.g. One specific user may not often use many admistrator utilities. If they suddenly try to access lots of sensitive management utilities, an attacker may have gained access to their account

#colbreak()

*Responding to Alarms:*
- Monitor and collect data about the situation
- Act to protect the system, like locking certain resources
- Alert a human to the situation

*Effectiveness:*
- IDSs can't be perfect. The degree of false positives and false negatives represents the sensitivity of the IDS, which can usually be tuned by a system administrator
- The Detection Rate (DR) is calculated by (TP)/(TP+FN)
- The Precision is calculated by (TP)/(TP+FP)
(TP = True Positive, FN = False Negative, FP = False Negative)

*Instrusion Prevention System (IPS):* IDS + Firewall
