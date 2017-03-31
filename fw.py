import sys

filenameConfig = sys.argv[1]
rules = []
try:
	# Read config file
	configFile = open(filenameConfig, "r")
	counter = 1
	rule = configFile.readline()
	while rule != "":
		commentCheck = rule.split()
		
		if len(commentCheck) > 0:
			if commentCheck[0].startswith('#') == False:
				
				if len(rule.split()) > 0:
					# Append line number
					rule = str(counter) + " " + rule
					
					#Parsing rules
					parsedRules = rule.split()
					
					if len(rule.split()) > 6:
						sys.stderr.write("Incorrect configuration file format\n")
						raise
					
					if parsedRules[len(parsedRules) - 1] == "":
						del parsedRules[len(parsedRules) - 1]
					
					IP = parsedRules[3]
					if IP == "*":
						mask = ""
					else:
						IP = IP.replace("/", ".")
						stringIP = ""
						parsedIP = IP.split(".")
						for i in range(4):
							num = parsedIP[i]
							num = int(num)
							stringIP += '{0:08b}'.format(num)
						
						mask = stringIP[:int(parsedIP[4])]
					parsedRules[3] = mask
					
					ports = parsedRules[4]
					if ports == "*":
						portList = []
					else:
						portList = ports.split(",")
					parsedRules[4] = portList
					
					if len(parsedRules) == 6:
						parsedRules[5] = "1"
					else:
						parsedRules.append("0")
						
					rules.append(parsedRules)
				
		rule = configFile.readline()
		counter += 1
	
	# Read packet file	
	packet = sys.stdin.readline()
	counter = 1
	while packet != "":
		# Change IP to hex string format
		parsedPacket = packet.split()
		if parsedPacket[len(parsedPacket) - 1] == "":
			del parsedPacket[len(parsedPacket) - 1]
		
		if len(parsedPacket) != 4:
			sys.stderr.write("Incorrect packet format\n")
			raise
		
		IP = parsedPacket[1]
		stringIP = ""
		parsedIP = IP.split(".")
		for i in range(4):
			num = parsedIP[i]
			num = int(num)
			stringIP += '{0:08b}'.format(num)
		
		parsedPacket[1] = stringIP
		
		ruleFound = False
		# Determine packet action
		for r in rules:
			if parsedPacket[0] == r[1]:
				if parsedPacket[2] in r[4] or len(r[4]) == 0:
					if parsedPacket[3] == r[5] or r[5] == "0":
						# Compare packet IP with rule mask
						if parsedPacket[1].startswith(r[3]):
							action = r[2]
							lineNum = r[0]
							ruleFound = True
							break
		
		if not ruleFound:
			action = "drop"
			lineNum = -1
		
		# Program output 
		result = action
		if lineNum == -1:
			result += "() " + parsedPacket[0] + " " + IP + " " + parsedPacket[2] + " " + parsedPacket[3]
		else:
			result += "(" + lineNum + ") " + parsedPacket[0] + " " + IP + " " + parsedPacket[2] + " " + parsedPacket[3]
			
		sys.stdout.write(result + "\n")
		packet = sys.stdin.readline()
		counter += 1
	
except:
	sys.stderr.write("Something went wrong, ending execution \n")
	
