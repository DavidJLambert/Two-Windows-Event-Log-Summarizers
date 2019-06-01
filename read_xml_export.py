""" read_xml_export.py
REPOSITORY:
  https://github.com/DavidJLambert/Two-Windows-Event-Log-Summarizers

SUMMARY:
  Scans XML exports of the Windows Event Log and reports summary statistics.

AUTHOR:
  David J. Lambert

VERSION:
  0.1.0

DATE:
  May 31, 2019
"""

# -------- IMPORTS.

from __future__ import print_function
import xml.etree.ElementTree
import win32security
from frozendict import frozendict
import glob
from zipfile import ZipFile
import os

# -------- CODE.


def handle_files():
    """ Driver program.  Find XML files in current directory.

    Args:
        none.
    Returns:
        none.
    Raises:
        none.
    """

    # Read and parse XML file(s).  First try to unzip any zipped files.
    xml_zip_files = glob.glob('./sample_data/*.xml.zip')
    if len(xml_zip_files) > 0:
        for xml_zip_file in xml_zip_files:
            with ZipFile(xml_zip_file, "r") as f:
                unzipped_name = xml_zip_file.replace(".zip", "")
                unzipped_exists = os.path.isfile(unzipped_name)
                if not unzipped_exists:
                    f.extractall("./sample_data")

    # Read and parse XML file(s).
    xml_files = glob.glob('./sample_data/*.xml')
    if len(xml_files) == 0:
        print("###  No XML files to process.")
        exit(1)

    output_start = "#"*10 + " "*2
    last_xml_file = xml_files[-1]
    for xml_file in xml_files:
        print("\n{}STARTING FILE '{}'.".format(output_start, xml_file[2:]))
        tree = xml.etree.ElementTree.parse(xml_file)
        events_root = tree.getroot()
        analyze_one_file(events_root)
        print("\n{}END OF FILE '{}'.".format(output_start, xml_file[2:]))
        if xml_file != last_xml_file:
            del events_root
            del tree


def analyze_one_file(events_root):
    """ Main analysis.  Go thru one file, compile statistics on contents.

    Args:
        events_root (object): root of the current XML node tree.
    Returns:
        none.
    Raises:
        none.
    """

    # Get tag_root, the start of the tag for each node in this XML tree.
    tag_root = events_root[0].tag.replace("Event", "")

    # To count children of level 2 node "event_node" (tag = tag_root+"Event").
    count_children = False
    if count_children:
        count_branch = {"Count": 0}

    # Nodes from subtree of level 3 node "sys_root".
    sys_nodes = {"EventID", "Version", "Level", "Task", "Opcode", "Keywords",
                 "Channel", "Computer"}
    # Fields of "Provider" node in subtree of level 3 node "sys_root".
    provider_fields = {"Name", "Guid", "EventSourceName"}
    # Nodes from subtree of level 3 node "render_root".
    render_nodes = {"Level", "Task", "Opcode", "Channel", "Provider"}

    # Map names in "sys_nodes" and "render_nodes" to Event Viewer field names.
    view_name = {"Provider": "Provider", "Channel": "Log Name"}
    for node in sys_nodes:
        if node != "Channel":
            view_name[node] = node

    # Map names in "provider_fields" to field names seen in Event Viewer.
    view_name["Name"] = "Provider"
    view_name["Guid"] = "Guid"
    view_name["EventSourceName"] = "Source Name"

    # Map names in "security_node" to field names seen in Event Viewer.
    view_name["UserID"] = "User Name"

    # Event summary.  The keys are values of "view_name".
    event_summary = dict.fromkeys(view_name.values())

    # Where we compile event statistics.
    event_stats = {}

    # Iterate over all records in the exported XML file.
    for event_node in events_root:
        # Count children of level 2 node "event_node" (tag = tag_root+"Event").
        if count_children:
            count_branch["Count"] += 1
            for child_node in event_node:
                branch = child_node.tag
                if branch not in count_branch:
                    count_branch[branch] = 1
                else:
                    count_branch[branch] += 1

        # The level 2 node "event_node" can have children with these tags:
        #     tag_root+"EventData", tag_root+"RenderingInfo", tag_root+"System",
        #     and tag_root+"UserData"
        # Each event always has a child with tag = tag_root+"System".
        # Each event always has a child with tag = tag_root+"EventData"
        #                                 or tag = tag_root+"UserData".

        # The level 3 node "sys_root", with tag = tag_root+"System".
        sys_root = event_node.find(tag_root + "System")

        # Get info from child nodes of level 3 node "sys_root".
        for node in sys_nodes:
            event_summary[view_name[node]] = find_field(sys_root, node,
                                                        tag_root)
        # Fields of the "Provider" node.
        provider_node = sys_root.find(tag_root + "Provider")
        for field in provider_fields:
            event_summary[view_name[field]] = sanitize(provider_node.get(field))

        # Fields of the "Security" node.
        security_node = sys_root.find(tag_root + "Security")
        event_summary["User Name"] = get_user_name(security_node.get("UserID"))

        # Level 3 node "render_root" (tag=tag_root+"RenderingInfo").
        render_root = event_node.find(tag_root + "RenderingInfo")
        if render_root is not None:
            # Get info from child nodes of level 3 node "render_root".
            for node in render_nodes:
                value = sanitize(find_field(render_root, node, tag_root))
                if value != "None":
                    event_summary[view_name[node]] = value
            # Fields of the "Keywords" node.
            keywords_node = render_root.find(tag_root + "Keywords")
            value = ""
            if keywords_node is not None:
                for keyword in keywords_node:
                    text = sanitize(keyword.text)
                    if text != "None":
                        if value == "":
                            value = text
                        else:
                            value += " " + text
                if value != "":
                    event_summary["Keywords"] = value

        # Translating int to str not done in "render_root", or no "render_root".
        event_summary["Opcode"] = opcode_name(event_summary["Opcode"])
        event_summary["Level"] = level_name(event_summary["Level"])
        event_summary["Keywords"] = keywords_name(event_summary["Keywords"])

        # print(event_summary)
        if frozendict(event_summary) in event_stats.keys():
            event_stats[frozendict(event_summary)] += 1
        else:
            event_stats[frozendict(event_summary)] = 1

    # The count of the children of level 2 node "event_node".
    if count_children:
        print(count_branch)

    # Print event stats
    for event_summary, count in sorted(event_stats.items(), reverse=True,
                                       key=lambda item: item[1]):
        print("\n##  {} occurrences of this event:".format(count))
        for key, value in event_summary.items():
            print(key + ": " + value)


def find_field(child, field_name, tag_root):
    """ Fetch specific fields of the child nodes of current the XML node.

    Args:
        child (object): child of node that may have field = field_name.
        field_name (string): name of field of XML node.
        tag_root (string): start of tag of each XML node in tree.
    Returns:
        text (string): text of the field with "field_name".
    Raises:
        none.
    """
    field = child.find(tag_root + field_name)
    if field is None:
        return ""
    else:
        return sanitize(field.text)


def sanitize(this):
    """ Convert object to string.

    Args:
        this (object).
    Returns:
        str(this).
    Raises:
        none.
    """
    if this is None:
        return "None"
    else:
        return str(this)


def get_user_name(sid):
    """ Translate from User SID to User Name.

    Args:
        PySID (object): contains a user's SID
        (See http://timgolden.me.uk/pywin32-docs/win32security.html).
    Returns:
        username (string): Windows user name with argument's SID.
    Raises:
        none.
    """
    if sid is None:
        return "None"
    else:
        py_sid = win32security.GetBinarySid(sid)
        return win32security.LookupAccountSid(None, py_sid)[0]


def level_name(level):
    """ Translate 'Level' Event Log field from int to descriptive string.

    Args:
        level (str(int)): severity level of event.
    Returns:
        severity (string).
    Raises:
        none.
    """
    name = {"0": "Information",
            "1": "Critical",
            "2": "Error",
            "3": "Warning",
            "4": "Information",
            "5": "Verbose"}
    if level in name.keys():
        return name[level]
    else:
        return sanitize(level)


def opcode_name(opcode):
    """ Translate 'Opcode' Event Log field from int to descriptive string.

    Args:
        Opcode (str(int)): event operation code.
    Returns:
        operation description (string).
    Raises:
        none.
    """

    """ Obtained by correlating values of 'Opcode' in the System and
    RenderingInfo subtrees.
       Made sure each value in System subtree always associated with same value
    in RenderingInfo subtree (not true of 'Task' field!).
       Sometimes two values in System subtree have same string in RenderingInfo
    subtree, these repetitions are not typos.
    """
    name = {"": "Info", "0": "Info",
            "1": "Start", "2": "Stop",
            "12": "Download", "13": "Installation",
            "62": "ServiceStart", "63": "ServiceStop",
            "68": "ServiceStart", "69": "ServiceStop",
            "104": "ServiceStopWithRefCount", "129": "ServiceShutdown"}
    if opcode in name.keys():
        return name[opcode]
    else:
        return sanitize(opcode)


def keywords_name(keywords):
    """ Translate 'Keywords' Event Log field from hex to descriptive string.

    Args:
        keywords (hexidecimal string)).
    Returns:
        keywords_name (string): keyword(s) corresponding to hexidecimal arg.
    Raises:
        none.
    """

    """ Obtained by correlating values of 'Keywords' field in the System subtree
    with the 'Keywords' subtree in the RenderingInfo subtrees
       Made sure each value in System subtree always associated with same value
    in RenderingInfo subtree (not true of 'Task' field!).
       Sometimes two values in System subtree have same string in RenderingInfo
    subtree, repetitions are not typos.
    """
    name = {"0x80000000000000": "Classic",
            "0x4000400000000001": "Core Events",
            "0x4000400000000002": "Helper Class Events",
            "0x8000000000000010": "Time",
            "0x8000000000000018": "Installation Success",
            "0x8000000000000028": "Installation Failure",
            "0x8000000000002004": "Download Started",
            "0x8000000000002008": "Installation Started",
            "0x8001000000000001": "Performance, Response Time",
            "0x8080000000000000": "Classic"}
    if keywords in name.keys():
        return name[keywords]
    else:
        return sanitize(keywords)


def flatten(node, tag_root):
    """ Flattens subtree of a node.

    Args:
        node (object): XML tree subtree.
    Returns:
        none.
    Raises:
        none.
    """

    """ Demo of flattening the subtree of the given node.  Alternative method
    of walking node tree.  Elegant, but not as efficient.
    """
    for child in node.iter():
        tag = child.tag.replace(tag_root, "").strip()
        child_text = child.text
        if child_text is not None:
            print(tag + ": " + child_text.strip())
        if len(child.attrib):
            for key, value in child.attrib.items():
                print(tag + "-" + key.strip() + ": " + value.strip())


if __name__ == '__main__':
        handle_files()
