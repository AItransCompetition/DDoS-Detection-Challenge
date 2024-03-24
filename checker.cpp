#include "testlib.h"
#include <string.h>
#include <assert.h>
#include <vector>
#include <utility>
#include <set>

inline int toInt(std::string s, int maxv) {
	int len = (int)s.length(), val = 0;
	for (int i = 0; i < len; i++) {
		quitif(s[i] < '0' || s[i] > '9', _wa, "Invalid IPv4 address.");
		val = val * 10 + s[i] - '0';
		quitif(val > maxv, _wa, "Invalid IPv4 address.");
	}
	return val;
}

inline std::string toIPv4(long long ip) {
	return std::to_string((ip >> 24) & 255) + "." + std::to_string((ip >> 16) & 255) + "." + std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}

int ps[10];
inline std::vector<std::pair<long long, int> > readIPv4AndLabels(InStream &f, int IP_cnt) {
	std::vector<std::pair<long long, int> > result;
	for (int i = 1; i <= IP_cnt; i++) {
		long long ip = 0;
		int label = -1;
		
		std::string s = f.readString();
		int cur = 0, cnt = 0, len = (int)s.length();

		quitif(s[len - 1] != '0' && s[len - 1] != '1' && s[len - 2] != ' ', _wa, "Label (0 or 1) expected.");
		label = s[len - 1] - '0';

		for (int i = 0; i < len - 2; i++) {
			if (s[i] == '.') ps[cnt++] = i;
			quitif(cnt > 3, _wa, "Invalid IPv4 address.");
		}
		quitif(cnt != 3, _wa, "Invalid IPv4 address.");
		ps[3] = len - 2;
		ip = toInt(s.substr(0, ps[0]), 255);
		ip = ip * 256 + toInt(s.substr(ps[0] + 1, ps[1] - ps[0] - 1), 255);
		ip = ip * 256 + toInt(s.substr(ps[1] + 1, ps[2] - ps[1] - 1), 255);
		ip = ip * 256 + toInt(s.substr(ps[2] + 1, ps[3] - ps[2] - 1), 255);

		result.push_back(std::make_pair(ip, label));
	}
	return result;
}


std::set<long long> attack_ips, normal_ips, ips, ouf_ips;

int main(int argc, char **argv) {
	registerLocalChecker(std::string(argv[1]), std::string(argv[2]), std::string(argv[3]), 100, std::string(argv[4]));

	int IP_cnt = ans.readInt(0, 1000000000);
	quitif(ouf.readInt(0, 1000000000) != IP_cnt, _wa, "Number of IP should be %d.\n", IP_cnt);
	ans.readEoln(), ouf.readEoln();

	int positive = 0, negtive = 0, correct = 0, true_positive = 0, false_positive = 0, false_negtive = 0;

	std::vector<std::pair<long long, int> > ip_list = readIPv4AndLabels(ans, IP_cnt);
	for (auto ip_label : ip_list) {
		long long ip = ip_label.first;
		int label = ip_label.second;

		assert(!ips.count(ip)), ips.insert(ip);
		if (label) attack_ips.insert(ip), positive += 1;
		else normal_ips.insert(ip), negtive += 1;
	}

	ip_list = readIPv4AndLabels(ouf, IP_cnt);
	for (auto ip_label : ip_list) {
		long long ip = ip_label.first;
		int label_predict = ip_label.second;

		quitif(!ips.count(ip), _wa, "No source IP: %s.\n", toIPv4(ip).c_str());
		quitif(ouf_ips.count(ip), _wa, "Duplicated source IP: %s.\n", toIPv4(ip).c_str());
		ouf_ips.insert(ip);

		int label = attack_ips.count(ip);
		if (label_predict == 1 && label == 1) true_positive += 1, correct += 1;
		else if (label_predict == 1 && label == 0) false_positive += 1;
		else if (label_predict == 0 && label == 1) false_negtive += 1;
		else correct += 1;
	}

	ans.readEof(), ouf.readEof();
	double accuracy = (double) correct / IP_cnt;
	double precision = (double) true_positive / (true_positive + false_positive);
	double recall = (double) true_positive / (true_positive + false_negtive);
	double F1_score = 2.0 * precision * recall / (precision + recall);

	quitp(F1_score * 100,
		"accuracy = %.2lf%%, precision = %.2lf%%, recall = %.2lf%%, F1_score = %.4lf.\n",
		accuracy * 100, precision * 100, recall * 100, F1_score);
	
	return 0;
}
