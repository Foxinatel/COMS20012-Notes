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
Users should not have access to private information that isn't relevant to them \
*Accountability:* Who did what? \
Ensure any action done by any user is logged and traceable \

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
=== Frame
- A chunk of data created by network communication hardware such as Network Interface Cards and router interfaces
- Frames contain frame delimiters, hardware addresses, and data encapsulated from higher layer protocols
=== Packets
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