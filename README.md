BitTorrent-uTP
==============

Bro scripts to identify local hosts that are using BitTorrent over UDP (via uTP)

Signature file scans all udp connections for the string "BitTorrent Protocol"

Sets service tag in conn.log to 'utp' for connections that had a peer connection observed

Other files (-log and -notify) can log the number of peers seen in a new log (utp.log) or to notice.log.

Michel Laterman (2015)
