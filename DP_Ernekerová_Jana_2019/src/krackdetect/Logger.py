import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from datetime import datetime

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }

global_log_level = ALL


def log(level, msg, color=None, showtime=True):
    """ default logger """
    if level < global_log_level:
        return
    if level == DEBUG and color is None:
        color = "gray"
    if level == WARNING and color is None:
        color = "orange"
    if level == ERROR and color is None:
        color = "red"
    print (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + \
           msg + "\033[1;0m"
