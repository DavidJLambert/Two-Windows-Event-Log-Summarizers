""" read_registry_direct.py
REPOSITORY:
  https://github.com/DavidJLambert/Two-Windows-Event-Log-Summarizers

SUMMARY:
  Scans XML exports of the Windows Event Log and reports summary statistics.

AUTHOR:
  David J. Lambert

VERSION:
  0.1.1

DATE:
  July 10, 2020
"""

# -------- IMPORTS.

from __future__ import print_function
from frozendict import frozendict
import traceback
import sys
import win32evtlog
import winerror
import win32security
# import win32con
# import win32evtlogutil

# -------- CODE.


def handle_logs() -> None:
    """ Driver program.  Iterate through desired Windows Event Logs.

    Args:
        none.
    Returns:
        none.
    Raises:
        none.
    """

    event_logs = ['System', 'Application']

    pre_output = "#"*10 + " "*2
    for event_log in event_logs:
        text = event_log.upper()
        print("\n{}STARTING {} EVENT LOG.".format(pre_output, text))
        analyze_one_log(event_log)
        print("\n{}END OF {} EVENT LOG.".format(pre_output, text))
# End of function handle_logs.


def analyze_one_log(event_log: str) -> None:
    """ Main analysis.  Go thru events in one event log, compile statistics.

    Args:
        event_log (string): name of Windows Event Log to read.
    Returns:
        none.
    Raises:
        none.
    """
    # Summary of one event.
    keys = ['EventID', 'Computer', 'Category', 'Source Name', 'Event Type',
            'User Name', 'Log Name']
    event_summary = dict.fromkeys(keys, "")
    # Where we compile event statistics.
    event_stats = {}
    # Handle to a Windows Event Log.
    handle = win32evtlog.OpenEventLog('localhost', event_log)
    # Flags for reading the Event Log.
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    # num_events = win32evtlog.GetNumberOfEventLogRecords(handle)

    try:
        events = 1
        while events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            for event in events:
                # Unpack each event.
                event_summary['EventID'] = winerror.HRESULT_CODE(event.EventID)
                event_summary['Computer'] = event.ComputerName
                event_summary['Category'] = event.EventCategory
                event_summary['Source Name'] = event.SourceName
                event_summary['Event Type'] = type_name(event.EventType)
                event_summary['User Name'] = get_user_name(event.Sid)
                event_summary['Log Name'] = event_log
                # record_num = event.RecordNumber
                # string_inserts = event.StringInserts
                # message = win32evtlogutil.SafeFormatMessage(event, event_log)

                # Tally statistics.
                if frozendict(event_summary) in event_stats.keys():
                    event_stats[frozendict(event_summary)] += 1
                else:
                    event_stats[frozendict(event_summary)] = 1
    except Exception:
        print(traceback.print_exc(sys.exc_info()))

    # Print event statistics.
    for event_summary, count in sorted(event_stats.items(), reverse=True,
                                       key=lambda item: item[1]):
        print("\n##  {} occurrences of this event:".format(count))
        for key, value in event_summary.items():
            print(str(key) + ": " + str(value))
# End of function analyze_one_log.


def type_name(event_type: int) -> str:
    """ Translate Event Type field from int to descriptive string.

    Args:
        event_type (int): severity level of event.
    Returns:
        severity (str).
    Raises:
        none.
    """
    name = {0: "Critical",
            1: "Error",
            2: "Warning",
            4: "Information"}
    if event_type in name.keys():
        return name[event_type]
    else:
        return sanitize(event_type)
# End of function type_name.


def get_user_name(py_sid) -> str:
    """ Translate from User SID to User Name.

    Args:
        PySID (object): contains a user's SID
        (See http://timgolden.me.uk/pywin32-docs/win32security.html).
    Returns:
        username (str): Windows user name with argument's SID.
    Raises:
        none.
    """
    if py_sid is None:
        return "None"
    else:
        return win32security.LookupAccountSid(None, py_sid)[0]
# End of function get_user_name.


def sanitize(this) -> str:
    """ Convert object to string.

    Args:
        this (object).
    Returns:
        this (str): str(this)
    Raises:
        none.
    """
    if this is None:
        return "None"
    else:
        return str(this)
# End of function sanitize.


if __name__ == '__main__':
        handle_logs()
