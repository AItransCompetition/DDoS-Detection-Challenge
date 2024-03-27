import polars as pl
def load_pkts(filepath: str, ids: set, total_pkts: dict, is_benign: dict):
	print(filepath)
	data = pl.read_csv(filepath, dtypes={'SimillarHTTP': str}, columns=["Flow ID", " Label"])
	pkts = data.select([
		pl.col("Flow ID").alias("id"),
		pl.col("Label").alias("label")
	])
	id_col = pkts["id"]
	label_col = pkts["label"]
	for (id, label) in zip(id_col, label_col):
		if not ids.__contains__(id):
			ids.add(id)
		if not label.__eq__("UNKNOWN"):
			is_benign[id] = 1 if label.__eq__("BENIGN") else 0
		if total_pkts.__contains__(id):
			total_pkts[id] += 1
		else:
			total_pkts[id] = 1

if __name__ == '__main__':
	ids = set()
	total_pkts = {}
	is_benign = {}

	load_pkts("test/SAT-03-11-2018_0.csv", ids, total_pkts, is_benign)
	for i in range (1, 146):
		load_pkts("test/SAT-03-11-2018_0{}.csv".format(i), ids, total_pkts, is_benign)

	threshold = 2
	with open("test/test_labels.txt", 'w') as f:
		f.write("{}\n".format(len(ids)))
		for id in ids:
			if total_pkts[id] > threshold:
				f.write("{}\n".format(id))
