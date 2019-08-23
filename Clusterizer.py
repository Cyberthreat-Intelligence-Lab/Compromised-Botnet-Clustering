import sys
if sys.version_info[0] < 3: 
    from StringIO import StringIO
else:
    from io import StringIO

import pandas as pd
import numpy as np
import csv
from scipy.cluster.hierarchy import fclusterdata
from scipy.special import rel_entr

def jensenshannon(p, q):
    p = np.asarray(p)
    q = np.asarray(q)
    p = p / np.sum(p, axis=0)
    q = q / np.sum(q, axis=0)
    m = (p + q) / 2.0
    left = rel_entr(p, m)
    right = rel_entr(q, m)
    js = np.sum(left, axis=0) + np.sum(right, axis=0)
    return np.sqrt(js / 2.0)

def chiSquared(p,q):
    return 0.5*np.sum((p-q)**2/(p+q+1e-6))

def to_distribution(p):
	p = p[1:-2]
	q = p.split(" ")
	float_list = []
	for i in range(len(q)):
		float_list.append(float(q[i]))
	return float_list

fileout = open("campaigns_by_address.csv", "w+")
tableout = open("campaigns_table.csv", "w+")

with open("PrimaryGroupings.txt") as datafile:
	count = 1
	id_num = 1
	dataline = datafile.readline().strip()
	table = pd.DataFrame(columns=['Id', 'Ports', 'Flag', 'ARR', '# of Bots', 'Distribution', '# of Packets'])
	print("Clustering Groups!")
	while len(dataline) != 0:
		campaigns = pd.DataFrame(columns=['Id', '# of Packets', 'IP Addresses'])
		addresses = dataline.split(",")
		if count % 1000 == 0:
			print("Grouping: " + str(count))
		pkt_counts = datafile.readline().strip().split(",")
		ports = datafile.readline().strip()
		flag = int(datafile.readline().strip())
		ARR = int(datafile.readline().strip())
		init_dists = datafile.readline().strip().split(";")
		distributions = [to_distribution(x) for x in init_dists]
		df = pd.DataFrame(distributions)
		x = df.values
		#if there is only one address
		if(len(x) == 1):
			temp = [[id_num, 0, addresses[0]]]
			temp[0][1] += int(pkt_counts[0])
			df1 = pd.DataFrame(temp)
			campaigns = pd.concat([campaigns, df1])

			table_values = [[id_num, ports, flag, ARR, 1, init_dists[0], int(pkt_counts[0])]]
			id_num += 1
			df2 = pd.DataFrame(table_values, columns=['Id', 'Ports', 'Flag', 'ARR', '# of Bots', 'Distribution', '# of Packets'])
			table = pd.concat([table, df2])
		#if there is only one port
		elif len(distributions[0]) == 1:
			temp = [[id_num, 0]]
			temp[0] += addresses
			int_counts = [int(x) for x in pkt_counts]
			temp[0][1] += sum(int_counts)
			df1 = pd.DataFrame(temp)
			campaigns = pd.concat([campaigns, df1])

			table_values = [[id_num, ports, flag, ARR, len(addresses), init_dists[0], sum(int_counts)]]
			id_num += 1
			df2 = pd.DataFrame(table_values, columns=['Id', 'Ports', 'Flag', 'ARR', '# of Bots', 'Distribution', '# of Packets'])
			table = pd.concat([table, df2])
		else:
			labels = fclusterdata(x, 0.15, criterion="distance", method="centroid",metric="chebyshev")
			#labels = fclusterdata(x, 0.05, criterion="distance", method="centroid",metric=jensenshannon)
			sorted_addresses = [[0] for x in xrange(max(labels))]
			table_values = [[ports, flag, ARR, 0, [], 0] for x in xrange(max(labels))]
			for i in range(len(labels)):
				index = labels[i] - 1
				sorted_addresses[index].append(addresses[i])
				sorted_addresses[index][0] += int(pkt_counts[i])
				table_values[index][3] += 1
				table_values[index][5] += int(pkt_counts[i])
			for i in range(len(sorted_addresses)):
				idx = addresses.index(sorted_addresses[i][1])
				sorted_addresses[i].insert(0, id_num)
				table_values[i].insert(0, id_num)
				pi = init_dists[idx]
				table_values[i][5] = pi
				id_num += 1
			df1 = pd.DataFrame(sorted_addresses)
			df2 = pd.DataFrame(table_values, columns=['Id', 'Ports', 'Flag', 'ARR', '# of Bots', 'Distribution', '# of Packets'])
			campaigns = pd.concat([campaigns, df1])
			table =pd.concat([table, df2])
		dataline = datafile.readline().strip()
		count += 1
		campaigns.to_csv(fileout, encoding="utf-8", index=False, header=False)
	table.to_csv(tableout, encoding="utf-8", index=False, header=False)
	print("Number of groupings processed: " + str(count - 1))
exit()



