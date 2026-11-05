"""Compatibility script; prefer python -m dns_analysis."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dns_analysis.__main__ import main
if __name__=='__main__': raise SystemExit(main())
