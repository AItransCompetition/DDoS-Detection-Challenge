import time
from scapy import *
from solver.solver import Solver
from utils.utils import load_pcap

def interaction(solver: Solver, packets, buffer_size):
    start_time = time.perf_counter_ns()

    results = []
    def report_infer_result(result: list[str, int]):
        infer_time = (time.perf_counter_ns() - start_time) / 1000000000
        results.append((infer_time, result))

    index = 0
    delay = 0
    while index < len(packets):
        current_time = (time.perf_counter_ns() - start_time) / 1000000000
        packets_to_be_infered = []
        
        while index < len(packets):
            timestamp, packet = packets[index]
            if timestamp <= current_time:
                if buffer_size == 0 or len(packets_to_be_infered) < buffer_size:
                    packets_to_be_infered.append((timestamp, packet))
                index += 1
                if index % 100000 == 0: print(index)
            else: break

        if len(packets_to_be_infered) == 0: continue
        # print(len(packets_to_be_infered))
        a = time.perf_counter_ns()
        solver.infer(packets_to_be_infered, report_infer_result)
        b = time.perf_counter_ns()
        delay += b - a

    print('total delay = %.3lf (s) and average delay = %.3lf (us).' % (delay / 1000000000, delay / len(packets) / 1000))
    return results

def write_infer_results(results, filepath):
    infered_flow_ids = set()
    with open(filepath, 'w') as f:
        for (infer_time, result) in results:
            for flow_id, label in result:
                if not infered_flow_ids.__contains__(flow_id): # only the first inference will not be ignored
                    f.write('%.9lf %s %d\n' % (infer_time, flow_id, label))
                    infered_flow_ids.add(flow_id)
    return infered_flow_ids

if __name__ == '__main__':
    solver = Solver()
    print('Initial solver finished.')

    config = {
        'pcap_path': './train.pcap',
        'buffer_size': 0, # 0 for no limit
        'result_path': './predict_labels.txt'
    }
    packets = load_pcap(config['pcap_path'])
    print('Load pcap finished with total %d packets.' % (len(packets)))

    results = interaction(solver, packets, config['buffer_size'])
    print('Interaction finished.')

    infered_flow_ids = write_infer_results(results, config['result_path'])
    print('All finished with infering %d flows.' % (len(infered_flow_ids)))
    
