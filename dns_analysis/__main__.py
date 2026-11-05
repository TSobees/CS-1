import argparse
import json
from pathlib import Path
from .analyze import analyze_capture

def main(argv=None):
    p=argparse.ArgumentParser(description='Analyze an existing capture offline without root privileges.')
    p.add_argument('capture',nargs='?',type=Path,default=Path(__file__).resolve().parents[1]/'data/dns.cap')
    p.add_argument('--output-dir',type=Path,default=Path('outputs'))
    p.add_argument('--write-filtered',action='store_true',help='Also create a DNS-only capture.')
    a=p.parse_args(argv)
    if a.write_filtered and (a.output_dir/'filtered_dns.pcap').resolve()==a.capture.resolve():
        p.error('Choose a different output directory; the capture cannot overwrite itself.')
    try:
        a.output_dir.mkdir(parents=True,exist_ok=True)
        report=analyze_capture(a.capture,a.output_dir/'filtered_dns.pcap' if a.write_filtered else None)
    except (OSError,ValueError,EOFError) as error: p.error(str(error))
    (a.output_dir/'dns_summary.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2));return 0

if __name__=='__main__': raise SystemExit(main())
