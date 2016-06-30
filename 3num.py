#!/usr/bin/python
'''
Full port scans and port enumeration for the masses!
@T0w3ntum
'''
import sys, re, os, subprocess, shlex
import xml.etree.ElementTree as ET
from optparse import OptionParser
from libnmap.parser import NmapParser, NmapParserException
from libnmap.process import NmapProcess
from tabulate import tabulate

# Further enumeration
def do_intense(IP,port_list,output_dir):
    print port_list
    if (445 in port_list or 139 in port_list or 135 in port_list):
        print "[+] Running enum4linux"
	cmd = "enum4linux %s" % (IP)
	args = shlex.split(cmd)
	out_file = "%s%s-enum4linux.txt" % (output_dir,IP)
        with open(out_file, 'w') as f:
            subprocess.call(args, stdout=f)
	print "[+] Enum4linux complete. You can view it here: %s" % (out_file)
    else:
        print "[-] Doesn't look like we can run enum4linux on this host."
    

# start a new nmap scan with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed;


# print scan results from a nmap report
def print_scan(nmap_report):
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)

# Generate LaTeX table and export to markdown with Pandoc
def do_generate_table(nmap_report,output_dir):
    for host in nmap_report.hosts:
	if len(host.hostnames):
		tmp_host = host.hostnames.pop()
	else:
	    tmp_host = host.address
	headers = ["PORT","STATE","SERVICE"]
	table = []
	for serv in host.services:
		table.append([str(serv.port)+"/"+serv.protocol, serv.state, serv.service])
	#print tabulate(table, headers, tablefmt="grid")
	out_file = "%s%s-ports-table.md" % (output_dir,tmp_host)
	md_header = "## %s Port Data\n\n" % (tmp_host)
	f = open(out_file, "w")
	f.write(md_header)
	f.write(tabulate(table, headers, tablefmt="grid"))
	f.write("\n\n")
	f.close()
	print "[+] Table data stored in %s%s-ports-table.md" % (output_dir,tmp_host)

# Get all the ports into a list
def get_ports(nmap_report):
    port_list = []
    for host in nmap_report.hosts:
        for serv in host.services:
            port_list.append(serv.port)
    return port_list;

# Main
if __name__ == "__main__":

    
    intro = """\
     .----------------.  .-----------------. .----------------.  .----------------. 
    | .--------------. || .--------------. || .--------------. || .--------------. |
    | |    ______    | || | ____  _____  | || | _____  _____ | || | ____    ____ | |
    | |   / ____ `.  | || ||_   \|_   _| | || ||_   _||_   _|| || ||_   \  /   _|| |
    | |   `'  __) |  | || |  |   \ | |   | || |  | |    | |  | || |  |   \/   |  | |
    | |   _  |__ '.  | || |  | |\ \| |   | || |  | '    ' |  | || |  | |\  /| |  | |
    | |  | \____) |  | || | _| |_\   |_  | || |   \ `--' /   | || | _| |_\/_| |_ | |
    | |   \______.'  | || ||_____|\____| | || |    `.__.'    | || ||_____||_____|| |
    | |              | || |              | || |              | || |              | |
    | '--------------' || '--------------' || '--------------' || '--------------' |
     '----------------'  '----------------'  '----------------'  '----------------' 
					@T0w3ntum
     """
    print intro

    # Set up arguments
    usage = '%prog -H HOST_IP'
    parser = OptionParser(usage=usage)
    parser.add_option('-H', '--host', type='string', action='store', dest='target_host', help='Target Host IP.')
    parser.add_option('-i', '--intense', action='store_true', dest='intense', help='Perform further enumeration tasks on found services')
    parser.add_option('-V', '--verbose', action='store_true', dest='verbose', help='Perform service identification')
    parser.add_option('-t', '--table', action='store_true', dest='to_table', help='Save nmap results to Markdown table -o required')
    parser.add_option('-o', '--output', action='store', type="string", dest="output_dir", help="Supply output directory for results. Trailing / required")
    (options, args) = parser.parse_args()
    IP = options.target_host
    if options.target_host is None:
        print "Missing host\n"
        parser.print_help()
        exit(-1)

    scan_op = "-T4 --open --min-rate=400 -p-"
    print "[+] Performing quick full port scan on %s" % (IP)
    report = do_scan(IP, scan_op)
    if report:
	print "[+] Parsing the results from quick scan"
    else:
	print("No results returned")

    # If -sV then do intense scan
    if options.verbose == True:
	print "[+] Running service identification scans."
        port_list = get_ports(report)
        ports = ",".join(map(str,port_list))
        scan_op = "-sT -A -p %s" % (ports)
        report = do_scan(IP, scan_op)
    else:
        port_list = get_ports(report)
    # Print out the results
    if report:
	print_scan(report)
	if options.to_table == True:
	    if options.output_dir:
	        do_generate_table(report,options.output_dir)
	    else:
	 	print "[-] Save output selected but no directory supplied. Use -o to supply directory"
    else:
	print("No results returned")

# Some future stuff here. 
    if options.intense == True:
	if options.output_dir:
            do_intense(IP,port_list,options.output_dir)
	else:
	    print "[-] Unable to run intense scans, no output directory selected. Use -o to supply output directory."



