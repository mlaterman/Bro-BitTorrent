BitTorrent-uTP
==============

Bro scripts to identify local hosts that are using BitTorrent over UDP (via uTP)

Signature file scans all udp connections for the string "BitTorrent Protocol"

Either creates a new log (utp.log) or writes to notice.log

Michel Laterman (2015)
