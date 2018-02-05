import sys
import multiprocessing
from multiprocessing import Pool, Process, Queue


class TaskMgr:
    def __init__(self, callback, fname, nprocess =  multiprocessing.cpu_count()):
        self.pool = Pool(nprocess)

        self.queue = multiprocessing.Manager().Queue()

        #consumer
        self.consumer = Process(target=callback, args=(self.queue, fname,))

    def run(self):
        self.consumer.start()

        self.pool.close()
        self.pool.join()

        self.queue.join()

        #perhaps never hit here
        self.consumer.join()
