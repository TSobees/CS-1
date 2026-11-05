"""Streaming analysis of existing captures; never captures or sends traffic."""
from collections import Counter
from pathlib import Path
from scapy.all import PcapReader, PcapWriter, DNS

RCODES={0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}

def analyze_capture(source, filtered_output=None):
    source=Path(source)
    if filtered_output is not None and Path(filtered_output).resolve()==source.resolve():
        raise ValueError('Filtered output must not overwrite the source capture.')
    total=dns_count=queries=responses=0;names=Counter();rcodes=Counter();types=Counter()
    writer=None
    try:
        with PcapReader(str(source)) as packets:
            if filtered_output is not None:
                writer=PcapWriter(str(filtered_output),append=False,sync=True,linktype=packets.linktype)
            for packet in packets:
                total+=1
                if not packet.haslayer(DNS): continue
                dns=packet[DNS];dns_count+=1
                if writer is not None: writer.write(packet)
                if int(dns.qr)==0:
                    queries+=1
                    # Iterate all questions, rather than assuming one question exists.
                    for question in dns.qd or []:
                        raw=question.qname
                        name=raw.decode('utf-8',errors='replace') if isinstance(raw,bytes) else str(raw)
                        names[name.rstrip('.')]+=1;types[str(question.qtype)]+=1
                else:
                    responses+=1;rcodes[RCODES.get(int(dns.rcode),str(dns.rcode))]+=1
    finally:
        if writer is not None: writer.close()
    return {'packets':total,'dns_packets':dns_count,'queries':queries,'responses':responses,
        'query_names':dict(names.most_common()),'query_types':dict(sorted(types.items())),
        'response_codes':dict(sorted(rcodes.items())),
        'interpretation':'NXDOMAIN or repeated names are observations, not proof of a malicious domain or unauthorized activity.'}
