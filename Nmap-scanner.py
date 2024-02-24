

import nmap

tryagain = True
while tryagain:
	tryagain = True
	target = input('[+] Enter the target website in the format of www.example.com:')
	#port scanner object created
	nm=nmap.PortScanner()
	#range of ports to scan
	rangel=input('[+] Enter the range of ports you wish to scan in the format of 1-100')
	nm.scan(target, rangel)
	#results are printed
	print(nm.csv())

	#print services running on open ports
	for host in nm.all_hosts():
		print('Host: %s (%s)' % (host, nm[host].hostname()))
		print('State: %s' % nm[host].state())
		for proto in nm[host].all_protocols(): 
			print('Protocol: %s' % proto)
			lport = nm[host][proto].keys()
			for port in lport:
				print('port: %s\tstate: %s' % (port, nm[host][proto][port]['state'])) 
				print('service: %s' % nm [host] [proto] [port]['name'])
				print('product: %s' % nm[host][proto] [port]['product'])
				print('version: %s' % nm [host][proto] [port]['version'])
				print('extrainfo: %s' % nm[host] [proto] [port]['extrainfo'])
				print('reason: %s' % nm[host][proto] [port]['reason'])
				print('cpe: %s' % nm [host][proto] [port]['cpe'])
				print('conf: %s' % nm [host] [proto][port]['conf'])
	#export to csv file
	with open('vulnerablePorts.csv', 'w') as f:
		f.write(nm.csv())
		f.close()
	userinp= input('The scan has been completed. Do you wish to run it again? (y/n)').lower() 	
	if userinp== 'y':
		tryagain = True
	elif userinp== 'n':
		print('Code exited.')
		tryagain = False
	else:
		print('Input unrecognized. Code exited.')
		tryagain = False