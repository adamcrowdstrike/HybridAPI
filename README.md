# HybridAPI
Author Adam Meyers

Quick tool for using Hybrid Analysis API on command line.

Requires: requests, optparse, requests.auth, time

Step 1: Get API/Key from http://www.hybrid-analysis.com

Step 2: Add your Hybrid Analysis API and KEY to line 48

Step 3: Hunt adversaries!

Optional: If you are using a private cloud version change line 16 to include your private cloud instance location.

Usage: `haapi.py [options]`

Options:

      -h, --help            show this help message and exit
      -d DNS, --dns=DNS     Query a DNS against Hybrid-Analysis
      -i IP, --ipv4=IP      Query a IP against Hybrid-Analysis
      -t TYPE, --type=TYPE  Query a File Type from Hybrid-Analysis
      -s SHA, --sha=SHA     Query a Sha256 from Hybrid-Analysis
      -v VXFAM, --vxfamily=VXFAM
                            Query a VXFamily from Hybrid-Analysis
