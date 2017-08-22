# README #

## firewall log analysis tool, written in Go ##

designed to be a quick analysis of a firewall log - used rules etc.. and looking for bad / interesting connections..

a bit (VERY) dirty at the moment

currently supports SRX only, could easily be extended..

areas to extend:
- CSV output or at least nicer output
- further device support
- automated pulling of bad ip lists
- further analysis of logs looking for unusual patterns

### potential bad ip lists ###

these are good basic lists to get started, focused on ransomware etc.. you'll need to format them to a single IP per line (no CSV)

-  https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt
- https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
- http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt
