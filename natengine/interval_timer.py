###############################################################################
# (c) 2022 Michael MacFadden
#
# CSC-841 Cyber Operations II
# Lab 08 and 09
###############################################################################

from threading import Thread
from time import sleep
from collections.abc import Callable

class IntervalTimer(Thread):
    """A utility class the executes a call back function on a supplied interval."""
    def __init__(self, name: str, callback: Callable[[], None], interval: int):
        Thread.__init__(self, name=name)
        
        self._callback = callback
        self._stopped = False
        self._interval = interval
        self.daemon = True

    def stop(self):
        self._stopped = True

    def run(self):
        while not self._stopped:
            sleep(self._interval)
            try:
                self._callback()
            except Exception as e:
                print(e)

            