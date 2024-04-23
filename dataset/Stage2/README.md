#### Download & Unzip

Please download & unzip the dataset from [https://cloud.tsinghua.edu.cn/d/2d4e04c81ca744b8b85c/](https://cloud.tsinghua.edu.cn/d/2d4e04c81ca744b8b85c/).

In this sub-problem, we introduce complex variations of features related to IPDs and packet sizes, etc., and initially introduce a mixture of different attack flow to slightly increase the difficulty of recognition, but the attack flow features still differ significantly from the background flow features. In addition, the training and test sets contain a total of three attacks, namely TCP RST Flood, TCP ACK Flood, TCP SYN Flood, UDP Flood, UDP Fragment Flood, DNS Flood, and HTTP GET Flood.

#### Format of train_labels.txt

The first line indicates the number of flows. Each flow is represented by a quintuple: {Source IP}-{Destination IP}-{Source Port}-{Destination Port}-{Protocol}. The submitted file's format should be the same.
