import json
import threading
import queue
from time import sleep
from datetime import datetime

logfile = None
write_queue = None

def start_logger(filename: str) -> None:
    global logfile, write_queue

    logfile = filename

    run_event = threading.Event()
    run_event.set()  # TODO clear() then cleanup() on program exit
    write_queue = queue.Queue()
    write_thread = threading.Thread(target=logger_write, args=(run_event,))
    write_thread.start()

def logger_write(run_event) -> None:
    while run_event.is_set():
        try:
            # buf = write_queue.get(block=False)
            buf = write_queue.get()
        except queue.Empty:
            sleep(0.1)
        else:
            with open(logfile, 'a') as fp:
                fp.write(buf)

def logger_add(data) -> None:
    write_queue.put(json.dumps(data))

def cleanup() -> None:
    write_queue.join()
