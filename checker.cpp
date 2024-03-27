#include "testlib.h"
#include <string>
#include <assert.h>
#include <set>

std::set<std::string> benign, predict;

int main(int argc, char **argv) {
	registerLocalChecker(std::string(""), std::string(argv[1]), std::string(argv[2]), 100, std::string(argv[3]));

	int flow_cnt = ans.readInt();
	if (ouf.readInt() != flow_cnt) quitp(0, "Wrong flow number.\n");
	ans.eoln(), ouf.eoln();

	while (true) {
		benign.insert(ans.readString());
		ans.eoln();
		if (ans.eof()) break;
	}

	int true_positive = 0;
	while (true) {
		std::string flow_id = ouf.readString();
		if (predict.count(flow_id)) quitp(0, "Duplicated flow id.\n");
		predict.insert(flow_id);
		if ((int)predict.size() > flow_cnt) quitp(0, "Too many flows.\n");
		if (benign.count(flow_id)) true_positive += 1;

		ouf.eoln();
		if (ouf.eof()) break;
	}

	int false_negtive = (int)benign.size() - true_positive;
	int false_positive = (int)predict.size() - true_positive;
	if (true_positive + false_positive + false_negtive > flow_cnt)
		quitp(0, "Too many flows.\n");
	int true_negtive = flow_cnt - (true_positive + false_positive + false_negtive);
	int correct = true_positive + true_negtive;

	if (true_positive == 0) quitp(0, "No True Positive...\n");
	long double accuracy = (long double) correct / flow_cnt;
	long double precision = (long double) true_positive / (true_positive + false_positive);
	long double recall = (long double) true_positive / (true_positive + false_negtive);
	long double F1_score = (long double) 2.0 * precision * recall / (precision + recall);

	quitp((double) F1_score * 100,
		"accuracy = %.2lf%%, precision = %.2lf%%, recall = %.2lf%%, F1_score = %.4lf.\n",
		(double) accuracy * 100, (double) precision * 100, (double) recall * 100, (double) F1_score);
	
	return 0;
}
