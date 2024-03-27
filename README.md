# DDoS-Detection-Challenge

This repository contains the DDoS-datasets for each stage, a reference format for the prediction labels to be submitted, judge script, and a few simple runnable sample programs.



### Judge script

The judge script will be logically similar to `checker.cpp`. The usage of this judge script is:

```bash
g++ checker.cpp -o checker -O2 -std=c++11
./checker [predict_labels] [correct_labels] [scorefile]
```

The `checker` will compare the two labels files and write the score  to the `[scorefile]`.
