from utils.utils import get_flow_id, load_pcap

def load_predict_labels(filepath: str):
    predict_labels = {}
    with open(filepath, 'r') as f:
        lines = f.readlines()
        for line in lines:
            infer_time, flow_id, label = line.split(' ')
            assert not predict_labels.__contains__(flow_id), 'Duplicate inference of %s' % flow_id
            predict_labels[flow_id] = (float(infer_time), int(label))
    return predict_labels

def load_flow_timestamp(filepath: str):
    pcap = load_pcap(filepath)
    flow_timestamp = {}
    for timestamp, packet in pcap:
        flow_id = get_flow_id(packet)
        if not flow_timestamp.__contains__(flow_id):
            flow_timestamp[flow_id] = []
        flow_timestamp[flow_id].append(timestamp)
    return flow_timestamp

def load_benign_flows(filepath: str):
    benign_flows = set()
    with open(filepath, 'r') as f:
        lines = f.readlines()
        for line in lines[1:]:
            flow_id = line.split('\n')[0]
            benign_flows.add(flow_id)
    return benign_flows

def calc_score(predict_labels: dict, benign_flows: set, flow_timestamp: dict, available_infer_delay: int):
    mtx = [[0, 0], [0, 0]]
    for flow_id, (infer_time, predict_label) in predict_labels.items():
        assert flow_timestamp.__contains__(flow_id), 'No such flow: %s' % (flow_id)
        correct_label = 1 if flow_id in benign_flows else 0
        timestamp_list = flow_timestamp[flow_id]
        flow_length = len(timestamp_list)
        
        if correct_label != predict_label:
            mtx[predict_label][correct_label] += flow_length
        else:
            mtx[1 - correct_label][correct_label] += flow_length
            for timestamp in timestamp_list:
                if infer_time <= timestamp + available_infer_delay / 1000000:
                    mtx[predict_label][correct_label] += 1
                    mtx[1 - correct_label][correct_label] -= 1
    
    for flow_id, timestamp_list in flow_timestamp.items():
        correct_label = 1 if flow_id in benign_flows else 0
        flow_length = len(timestamp_list)
        if not predict_labels.__contains__(flow_id):
            mtx[1 - correct_label][correct_label] += flow_length
    
    TP, TN, FP, FN = mtx[1][1], mtx[0][0], mtx[1][0], mtx[0][1]
    assert TP > 0, 'No True Positive.'
    accuracy = (TP + TN) / (TP + TN + FP + FN)
    precision = TP / (TP + FP)
    recall = TP / (TP + FN)
    F1_score = 2.0 * precision * recall / (precision + recall)
    print(TP, TN, FP, FN, TP + TN + FP + FN, accuracy, precision, recall, F1_score)
    return F1_score

if __name__ == '__main__':
    config = {
        'pcap_path': './train.pcap',
        'predict_labels': './predict_labels.txt',
        'correct_labels': './train_labels.txt',
        'available_infer_delay': 2000 # us, may be changed before opening the online submission
    }

    predict_labels = load_predict_labels(config['predict_labels'])
    print('Load predict labels finished with %d infered flow.' % len(predict_labels))
    
    benign_flows = load_benign_flows(config['correct_labels'])
    print('Load correct labels finished with %d benign flow.' % len(benign_flows))
    
    flow_timestamp = load_flow_timestamp(config['pcap_path'])
    print('Load flow timestamp finished with %d flow.' % (len(flow_timestamp)))
    
    score = calc_score(predict_labels, benign_flows, flow_timestamp, config['available_infer_delay'])
    print('F1 score = %.2lf%%' % (score))