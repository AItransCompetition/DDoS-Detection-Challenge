#### Download & Unzip

Please download & unzip the dataset from [https://www.unb.ca/cic/datasets/ddos-2019.html](https://www.unb.ca/cic/datasets/ddos-2019.html).

This task expects the contestant to consider the dataset generated on the first day as a training dataset and the dataset generated on the second day as a test dataset, train with the labels from the training dataset as well as the issued training set, and generate prediction labels in the same format on the test dataset and submit them to the website for testing.

#### Format of train_labels.txt

The first line indicates the number of flows. Each flow is represented by a quintuple: {Source IP}-{Destination IP}-{Source Port}-{Destination Port}-{Protocol}.

The submitted file's format should be the same.