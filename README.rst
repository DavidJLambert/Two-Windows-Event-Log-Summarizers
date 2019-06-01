Two Windows Event Log Summarizers
---------------------------------

SUMMARY:
  - Two programs for summarizing the contents of a Windows Event Log:
    read_registry_direct.py, and read_xml_export.py.
  - https://github.com/DavidJLambert/Two-Windows-Event-Log-Summarizers

AUTHOR:
  David J. Lambert

DATE:
  May 31, 2019

PURPOSE:
  Windows Event Logs list events in Windows.  Windows Event Logs can be filtered
  and sorted according to various fields, such as Event ID, Level, and Source,
  but they cannot do more extensive analyses, such as counting the number of
  events with the same Event ID and Level.  Two programs, read_xml_export.py and
  read_registry_direct.py, fill that gap different ways by showing how many
  events in an Event Log have the same Event ID, Level, etc.
  
  + read_xml_export.py parses an XML export of an event log using the Python
    Standard Library xml.etree.ElementTree.
  + read_registry_direct.py directly reads events from an event Log using the
    library PyWin32.
  
  Details are provided below.
  
DESCRIPTION:
  Windows Event Logs list events in Windows, and each event has a number of
  fields, each containing a different piece of information about the event.

  This program has only been tried on Windows 10, whose Event Log contains a
  core group of fields in every event plus a variable number of other optional
  fields, all of whose names and values can be extracted using the library
  xml.etree.ElementTree.
  
  The PyWin32 library was written in the year 2000 for Windows 2000, and runs
  without problems on Windows 10, but it only reads a set core fields from the
  Event Log, and those fields' names are sometimes different from those used in
  Windows 10.
  
  Here are the field names used by PyWin32 and in exported Event Log XML file.
  Corresponding fields are on the same row.
    
  +---------------------------+----------------------------------------------+
  |        Field Names        |                                              |
  +-------------+-------------+                Field Contents                +
  | Win 10 XML  | PyWin32     |                                              |
  +=============+=============+==============================================+
  | EventID     | EventID     | Numeric code.                                |
  +-------------+-------------+----------------------------------------------+
  | Computer    | Computer    | Name of computer that event occurred on.     |
  +-------------+-------------+----------------------------------------------+
  | User Name   | User Name   | User name the process was logged in as.      |
  +-------------+-------------+----------------------------------------------+
  | "Log Name"  | Log Name    | "Application", "System", etc.                |
  | or "Channel"|             |                                              |
  +-------------+-------------+----------------------------------------------+
  |             |             | "Critical", "Error", "Warning",              |
  | Level       | Event Type  | "Information", or (in Win 10 only),          |
  |             |             | "Verbose"                                    |
  +-------------+-------------+----------------------------------------------+
  | Task        | Category    | A numeric code specific to each Source Name. |
  +-------------+-------------+----------------------------------------------+
  | Source Name | Source Name | Process name that generated this event.      |
  +-------------+-------------+----------------------------------------------+
  | Provider    |             | Synonym for Source Name.                     |
  +-------------+-------------+----------------------------------------------+
  | Guid        |             | Corresponds to Source Name.                  |
  +-------------+-------------+----------------------------------------------+
  | Version     |             | Event Log version?                           |
  +-------------+-------------+----------------------------------------------+
  | Opcode      |             | Numeric code for operation being logged.     |
  +-------------+-------------+----------------------------------------------+
  | Keywords    |             | Keywords for event.                          |
  +-------------+-------------+----------------------------------------------+

  These two programs record these fields, then group all events with the same
  values of these fields, counts the number of events in each group, and prints
  these fields and their count in descending order in the count.   

HOW TO EXPORT A WINDOWS EVENT LOG:
  + Start up the "Windows Settings" app.
  + In the search bar, enter "event logs", and select "View event logs".  The
    Event Viewer will start up.
  + Make the the Console Tree pane visible on the left.  If it is not visible,
    and you don't know how to make it visible, please consult Windows
    documentation for instructions on how to do that.
  + Under the "Event Viewer (Local)" node in the Console Tree should be four
    nodes: "Custom Views", "Windows Logs", "Applications and Services Logs",
    and "Subscriptions".  Except maybe for "Subscriptions", all of them should
    have a set of nodes under them: each of them is an individual Event Log.
  + Right-click on an individual Event Log.  Select the option saying something
    like "Save all Events As...".  You'll get the standard file save dialog.
  + In the "Save as type" selection just below file save, select "XML".
  + Be sure to allow time for the event log to get written to file.  The "Save
    all Events As..." dialog exits as soon as you the "OK" button, before
    all events are saved. 
  + Note that you can save the events for more than one Event Log by defining a
    custom event log under Custom Views that includes the Event Logs you want. 

OTHER LIBRARIES FOR PARSING XML:
  There are a variety of libraries available for parsing XML code.  My choice,
  xml.etree.ElementTree, is quite popular, and is part of the Python Standard
  Library.  A number of other libraries are listed in the StackOverFlow article
  https://stackoverflow.com/questions/1912434/how-do-i-parse-xml-in-python:

    + lxml
    + minidom
    + BeautifulSoup
    + xmltodict
    + xml.parsers.expat
    + untangle

HOW TO ACCESS NODES IN THE XML TREE:
  I chose to use XPath notation to find specific entries in the XML node subtree
  for each event.  This method is quite fast, as it ignores other entries.
  
  Another good method is to "flatten" the XML node subtree for each event.  My
  code includes a sample function (named "flatten") that does this, but I chose
  to not use it because it is slower: every node in subject to some processing,
  and relative positioning in the subtree is not as obvious.  But if performance
  is not important, this is a viable choice.  

DIRECTLY ACCESSING THE EVENT LOG:
  Instead of having to export event logs to XML, a valid choice is to directly
  access the Windows Event Log.  Two excellent choices exist for doing this:
  importing Pywin32, and using IronPython and the .NET Framework.
  
  Pywin32 makes a lot of the Win32 API available to Python, and can do much more
  than directly accessing the Windows Event Log.  I use it in both programs to
  translate the User SIDs found in the Event Log into User Names.

  IronPython can call the .NET Framework infrastructure, part of which can
  access Windows Event Logs.