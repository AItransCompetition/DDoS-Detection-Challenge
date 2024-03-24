from scapy.all import *
import numpy as np
from numpy import float64, ndarray
import xgboost as xgb
from sklearn.model_selection import train_test_split

from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score
from bayes_opt import BayesianOptimization

from algorithms.utils.tools import *

ipd_cliper = 10000
pkt_per_flow = 1000

maxLen = 0
maxIpd = 0

def load_pkts(filepath: str, pkts: list[tuple, int, int, int]):
	global maxLen, maxIpd
	_pkts = []
	fast_load_pkts(filepath, _pkts)
	for i in range(len(_pkts)):
		src, _len, ipd, label = _pkts[i]
		cliped_ipd = min(ipd_cliper, ipd)
		maxLen = max(maxLen, _len)
		maxIpd = max(maxIpd, cliped_ipd)
		pkts.append((src, _len, cliped_ipd, label))
		if i > 60000:
			break

def getXY(Q: int, trun_dict: dict[int, int], pkts: list[tuple, int, int, int], dataset_type: int) -> tuple[ndarray, ndarray, list[int]]:
	Flow_table = {}
	pkt_num = {}
	regs = []
	y = []
	flowids = []

	for (flow_feat, Len, Ipd, label) in pkts:
		ft = [Len, Ipd]
		Qlen = ft[dataset_type] // Q

		if not Flow_table.__contains__(flow_feat) or pkt_num[flow_feat] == pkt_per_flow:
			regs.append([0 for _ in range(len(trun_dict))])
			y.append(label)
			Flow_table[flow_feat] = len(y) - 1
			pkt_num[flow_feat] = 0

		flowid = Flow_table[flow_feat]
		flowids.append(flowid)
		pkt_num[flow_feat] = pkt_num[flow_feat] + 1

		if trun_dict.__contains__(Qlen):
			binid = trun_dict[Qlen]
			regs[flowid][binid] = regs[flowid][binid] + 1

	X, y = np.array(regs), np.array(y)
	return X, y, flowids


def train(X, y) -> tuple[ndarray, np.float64, xgb.XGBClassifier]:
	print(X.shape)
	X_train, X_test, y_train, y_test  = train_test_split(X, y, test_size = 0.2, random_state = 123)
	model = xgb.XGBClassifier(
		objective = 'binary:logistic',
		n_estimators = 1,
		max_depth = 4,
		early_stopping_rounds = 10,
	).fit(X_train, y_train, eval_set = [(X_test, y_test)], verbose = False)

	y_pred = model.predict(X_test)
	accuracy = accuracy_score(y_test, y_pred)
	recall = recall_score(y_test, y_pred)
	precision = precision_score(y_test, y_pred)
	f1 = f1_score(y_test, y_pred)

	# print("accuracy: %.2f%%, recall: %.2f%%, precision: %.2f%%, f1-score: %.2f%%" % (accuracy * 100, recall * 100, precision * 100, f1 * 100))

	return_score = f1
	return model.feature_importances_, return_score, model

def get_trun_dict(kfts: ndarray) -> dict[int, int]:
	trun_dict: dict[int, int] = {}
	for i in range(len(kfts)):
		trun_dict[kfts[i]] = i
	return trun_dict

def get_first_k_index(a: ndarray, k: int) -> ndarray:
	b = np.argsort(-a)
	return b[0 : min(k, len(b))]

def get_topk_features(Q: int, max_trunc_num: int, pkts: list[tuple, int, int, int], dataset_type: int) -> ndarray:
	global maxLen, maxIpd
	lim = [maxLen, maxIpd]
	max_bin_num = lim[dataset_type] // Q
	trun_dict = get_trun_dict([i for i in range(max_bin_num)])
	X, y, _ = getXY(Q, trun_dict, pkts, dataset_type)
	importances, _, __ = train(X, y)
	k = min(max_bin_num, max_trunc_num)
	return get_first_k_index(importances, k)

def get_acc_model(Q: int , kfts: ndarray, pkts: list[tuple, int, int, int], dataset_type: int) -> tuple[float64, xgb.XGBClassifier]:
	trun_dict = get_trun_dict(kfts)
	X, y, _ = getXY(Q, trun_dict, pkts, dataset_type)
	_, accuracy, model = train(X, y)
	return accuracy, model

def get_kfts_acc_model(Q: int, max_trunc_num: int, pkts: list[tuple, int, int, int], dataset_type: int) -> tuple[ndarray, float64, xgb.XGBClassifier]:
	kfts = get_topk_features(Q, max_trunc_num, pkts, dataset_type)
	acc, model = get_acc_model(Q, kfts, pkts, dataset_type)
	return kfts, acc, model

def eval(model: xgb.XGBClassifier, Q: int, kfts: ndarray, pkts: list[tuple, int, int, int], dataset_type: int):
	trun_dict = get_trun_dict(kfts)
	X, y, flowids = getXY(Q, trun_dict, pkts, dataset_type)
	y_pred = model.predict(X)
	results = {}

	for (i, pkt) in zip(range(len(pkts)), pkts):
		flow_feat = pkt[0]
		flowid = flowids[i]
		label_pred = y_pred[flowid]

		if not results.__contains__(flow_feat):
			results[flow_feat] = [0, 0]
		results[flow_feat][label_pred] = results[flow_feat][label_pred] + 1

	good_flow_feats = []
	bad_flow_feats = []
	for (flow_feat, result) in results.items():
		if result[0] > result[1]:
			good_flow_feats.append(flow_feat)
		else:
			bad_flow_feats.append(flow_feat)

	accuracy = accuracy_score(y, y_pred)
	recall = recall_score(y, y_pred)
	precision = precision_score(y, y_pred)
	f1 = f1_score(y, y_pred)

	return accuracy, recall, precision, f1, sorted(good_flow_feats), sorted(bad_flow_feats)

def Bayesian_find_best_QT(QLrange: tuple[int, int], Trange: tuple[int, int], pkts: list[tuple, int, int], dataset_type: int, n_iter: int = 30) -> tuple[int, int]:
	def get_acc(QL, T):
		_, acc, __ = get_kfts_acc_model(1 << int(QL), int(T), pkts, dataset_type)
		return acc
	optimizer = BayesianOptimization(
		f = get_acc,
		pbounds = {
			'QL': QLrange,
			'T': Trange
		},
		random_state = 233,
		verbose = 2
	)
	optimizer.maximize(
		n_iter = n_iter
	)
	res = optimizer.max
	return int(1 << int(res['params']['QL'])), int(res['params']['T'])



if __name__ == '__main__':
	Qlist = [16, 32, 64, 128, 256, 512]
	QLrange = (0.01, 8.99)
	Trange = (4, 64.99)
	dataset_type = 0

	print("Loading train packets...")
	pkts = []
	load_pkts('./dataset/baseline/DNS-Flood.csv', pkts)
	load_pkts('./dataset/baseline/UDP-Flood.csv', pkts)
	load_pkts('./dataset/baseline/ACK-Flood.csv', pkts)
	load_pkts('./dataset/baseline/RST-Flood.csv', pkts)
	load_pkts('./dataset/baseline/BG2.csv', pkts)
	# fast_load_cic_pkts('./dataset/CICDataset/03-11/UDP.csv', pkts)
	print("Finished.")
	print("number of bad pkts / number of all pkts = %.2f%%" % (sum([pkt[3] for pkt in pkts]) / len(pkts) * 100))

	print("\nTraining...")
	best_Q, best_T = Bayesian_find_best_QT(QLrange, Trange, pkts, dataset_type, 5)
	best_kfts, acc, model = get_kfts_acc_model(best_Q, best_T, pkts, dataset_type)
	print("Finished.")


	print("\nLoading test packets...")
	eval_pkts = []
	load_pkts('./dataset/baseline/SYN-Flood.csv', pkts)
	load_pkts('./dataset/baseline/UDP-Fragment.csv', eval_pkts)
	load_pkts('./dataset/baseline/HTTP-GET-Flood.csv', eval_pkts)
	load_pkts('./dataset/baseline/BG3.csv', eval_pkts)

	# fast_load_cic_pkts('./dataset/CICDataset/03-11/UDPLag.csv', eval_pkts)
	acc, rec, prec, f1, good_flow_feats, bad_flow_feats = eval(model, best_Q, best_kfts, eval_pkts, dataset_type)

	print("accuracy: %.2f%%, recall: %.2f%%, precision: %.2f%%, f1-score: %.2f%%" % (acc * 100, rec * 100, prec * 100, f1 * 100))

	# print(good_flow_feats)

	# normal_src = [socket.inet_ntoa(struct.pack("<L", src)) for src in good_flow_feats]
	# bad_src = [socket.inet_ntoa(struct.pack("<L", src)) for src in bad_flow_feats]
	# print("normal source IPs: ", normal_src)
	# print("attack source IPs: ", bad_src)

	# with open("predict.txt", "w") as file:
	# 	file.write("%d\n" % (len(bad_src) + len(normal_src)))
	# 	for src in bad_src:
	# 		file.write("%s %d\n" % (src, 1))
	# 	for src in normal_src:
	# 		file.write("%s %d\n" % (src, 0))
