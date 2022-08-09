# ezScan
**IN PROGRESS*
automated network scanning and parsing that I began working on in July 2022 during my red-team internship


Dependencies:
python3, python-nmap module

How to run:
1) Copy ezScan.py to a directory
2) Create a file named 'hosts.txt' in the same directory with a list of in-scope hosts (CIDR Notation, IP ranges, IPv4, IPv6, anything nmap would normally take with a new line break in between hosts)
3) Run with: python ezScan.py
