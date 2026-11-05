from pathlib import Path
import tempfile
import unittest
from scapy.all import Ether,IP,UDP,DNS,DNSQR,wrpcap,rdpcap
from dns_analysis.analyze import analyze_capture

class DNSTests(unittest.TestCase):
    def test_queries_responses_and_source_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'input.pcap';out=Path(tmp)/'dns.pcap'
            ethernet=lambda: Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')
            packets=[ethernet()/IP(src='192.0.2.2',dst='192.0.2.1')/UDP(dport=53)/DNS(qd=DNSQR(qname='example.test')),
                ethernet()/IP(src='192.0.2.1',dst='192.0.2.2')/UDP(sport=53)/DNS(qr=1,rcode=3,qd=DNSQR(qname='example.test')),
                ethernet()/IP(src='192.0.2.2',dst='192.0.2.1')/UDP(dport=9999)]
            wrpcap(str(source),packets);original=source.read_bytes();result=analyze_capture(source,out)
            self.assertEqual((result['packets'],result['dns_packets'],result['queries'],result['responses']),(3,2,1,1))
            self.assertEqual(result['response_codes'],{'NXDOMAIN':1});self.assertEqual(result['query_names'],{'example.test':1})
            self.assertEqual(source.read_bytes(),original);self.assertEqual(len(rdpcap(str(out))),2)
    def test_source_overwrite_rejected(self):
        with self.assertRaises(ValueError): analyze_capture('same.pcap','same.pcap')
    def test_bundled_capture(self):
        source=Path(__file__).resolve().parents[1]/'data/dns.cap'
        report=analyze_capture(source)
        self.assertGreater(report['packets'],0)
        self.assertEqual(report['queries']+report['responses'],report['dns_packets'])
    def test_missing_capture(self):
        with self.assertRaises(OSError): analyze_capture('missing-capture.pcap')

if __name__=='__main__': unittest.main()
