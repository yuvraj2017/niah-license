import json



def fucn(ecosystem, product):
with open("/var/DB/feeds/deps/%s_dep.json" % ecosystem, "r") as f:
	jsondata = json.load(f)



packagename = 'urllib3'


results = {}
results[packagename] = {}

for p1 in jsondata[packagename]:
	results[packagename][p1] = {}
	if p1 in jsondata:
		if len(jsondata[p1]) > 0:
			for p2 in jsondata[p1]:
				results[packagename][p1][p2] = {}
				if p2 in jsondata:
					if len(jsondata[p2]) > 0:
						for p3 in jsondata[p2]:
							results[packagename][p1][p2][p3] = {}
							if p3 in jsondata:
								if len(jsondata[p3]) > 0:
									for p4 in jsondata[p3]:
										results[packagename][p1][p2][p3][p4] = {}
										if p4 in jsondata:
											if len(jsondata[p4]) > 0:
												for p5 in jsondata[p4]:
													results[packagename][p1][p2][p3][p4][p5] = {}
					

print(results)
