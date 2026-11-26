"""Tiny local authoritative DNS server for AegisAI offline DNS-recon labs.

Serves aegis-lab.local on 127.0.0.1:53 so dnsrecon/dig never query the internet.
Start with sudo (port 53 is privileged):

    sudo python3 dns_lab_server.py
"""

import threading

from dnslib import A, AAAA, MX, NS, PTR, QTYPE, RR, SOA, TXT
from dnslib.server import BaseResolver, DNSServer

ZONE = "aegis-lab.local."

RECORDS = {
    ZONE: {"A": "127.0.0.1", "NS": "ns1." + ZONE,
           "SOA": "ns1.aegis-lab.local. hostmaster.aegis-lab.local. 1 3600 600 86400 3600",
           "TXT": "AegisAI local DNS recon lab zone"},
    "www." + ZONE: {"A": "127.0.0.1"},
    "api." + ZONE: {"A": "127.0.0.1"},
    "dev." + ZONE: {"A": "127.0.0.1"},
    "staging." + ZONE: {"A": "127.0.0.1"},
    "mail." + ZONE: {"A": "127.0.0.1", "MX": "10 mail." + ZONE},
    "admin." + ZONE: {"A": "127.0.0.1"},
    "ns1." + ZONE: {"A": "127.0.0.1"},
    "1.0.0.127.in-addr.arpa.": {"PTR": "www." + ZONE},
    "2.0.0.127.in-addr.arpa.": {"PTR": "api." + ZONE},
}


class LabResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        entry = RECORDS.get(qname, {})
        value = entry.get(qtype)

        if value:
            if qtype == "A":
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(value), ttl=60))
            elif qtype == "AAAA":
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(value), ttl=60))
            elif qtype == "TXT":
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(value), ttl=60))
            elif qtype == "NS":
                reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(value), ttl=60))
            elif qtype == "SOA":
                reply.add_answer(RR(qname, QTYPE.SOA, rdata=SOA(value), ttl=60))
            elif qtype == "MX":
                priority, host = value.split(" ", 1)
                reply.add_answer(RR(qname, QTYPE.MX, rdata=MX(int(priority), host), ttl=60))
            elif qtype == "PTR":
                reply.add_answer(RR(qname, QTYPE.PTR, rdata=PTR(value), ttl=60))
        return reply


def main():
    resolver = LabResolver()
    udp = DNSServer(resolver, port=53, address="127.0.0.1", tcp=False)
    tcp = DNSServer(resolver, port=53, address="127.0.0.1", tcp=True)
    threading.Thread(target=tcp.start, daemon=True).start()
    print("AegisAI lab DNS listening on 127.0.0.1:53 for aegis-lab.local", flush=True)
    udp.start()


if __name__ == "__main__":
    main()
