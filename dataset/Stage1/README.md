#### Download & Unzip

Please download & unzip the dataset from [https://cloud.tsinghua.edu.cn/d/2c1eb9ebca1748239f0c/](https://cloud.tsinghua.edu.cn/d/2c1eb9ebca1748239f0c/).

In this sub-problem, in order to facilitate the initial testing of the designed algorithms by the contestants, we generated as a dataset the simpler attack flow with statistical characteristics close to each other, and the background flow with large differences, and the difference between the traffic feature distributions of the training set and the test set is small. In the training and test sets, we initially include four attack types, TCP ACK Flood, TCP RST Flood, TCP SYN Flood, and UDP Flood, as well as several types of background flows with simpler behaviors.

#### Format of train_labels.txt

The first line indicates the number of flows. Each flow is represented by a quintuple: {Source IP}-{Destination IP}-{Source Port}-{Destination Port}-{Protocol}. The submitted file's format should be the same.
