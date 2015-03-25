signature bittorrent-utp {
    ip-proto == udp
    payload /.*BitTorrent protocol/
    event "bittorrent-utp"
}
