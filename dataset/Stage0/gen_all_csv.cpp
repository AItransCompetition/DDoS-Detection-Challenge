#include<bits/stdc++.h>
using namespace std;
char s[10000],csv[1000],cap[1000];
int main()
{
	system("g++ ./../../pcap2csv.cpp -o pcap2csv -O2 -lpcap");
	system("./pcap2csv test_dataset/SAT-03-11-2018_0 test_dataset/SAT-03-11-2018_0.csv");
	for(int i=1;i<=145;i++)
	{
		sprintf(cap,"test_dataset/SAT-03-11-2018_0%d",i);
		sprintf(csv,"test_dataset/SAT-03-11-2018_0%d.csv",i);
		sprintf(s,"./pcap2csv %s %s",cap,csv), system(s);
	}

    system("./pcap2csv train_dataset/SAT-01-12-2018_0 train_dataset/SAT-01-12-2018_0.csv train_dataset/train_labels.txt");
	for(int i=1;i<=818;i++)
	{
		sprintf(cap,"train_dataset/SAT-01-12-2018_0%d",i);
		sprintf(csv,"train_dataset/SAT-01-12-2018_0%d.csv",i);
		sprintf(s,"./pcap2csv %s %s train_dataset/train_labels.txt",cap,csv), system(s);
	}

	return 0;
}