#!/usr/bin/env python3
"""The .msrcIncident file FreeRDP's /assistance mode reads, around an RDPSRAPI
invitation's connection string (the RCTICKET). Usage: incident.py INV.txt > f.msrcIncident"""
import sys
from xml.sax.saxutils import quoteattr
ticket = open(sys.argv[1], encoding="ascii").read().strip()
print('<?xml version="1.0" encoding="UTF-8"?>')
print(f'<UPLOADINFO TYPE="Escalated"><UPLOADDATA USERNAME="paguro" RCTICKET={quoteattr(ticket)} '
      'RCTICKETENCRYPTED="0" PassStub="" DtStart="" DtLength="" L="0"/></UPLOADINFO>')
