
import random
from utils import get_flow_id

# TODO: The following 2 functions (__init__ and infer) should be implemented.
class Solver:
    def __init__(self):
        pass

    def infer(self, packets, report_infer_result_func):
        for timestamp, packet in packets:
            flow_id = get_flow_id(packet)
            result = [(flow_id, random.randint(0, 1))]
            report_infer_result_func(result)