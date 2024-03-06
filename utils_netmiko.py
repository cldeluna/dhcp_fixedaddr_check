#!/usr/bin/python -tt
# Project: network_refresh
# Filename: utils_netmiko
# claudia
# PyCharm

from __future__ import absolute_import, division, print_function

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "5/2/21"
__copyright__ = "Copyright (c) 2018 Claudia"
__license__ = "Python"

import argparse
import netmiko
import os
import sys
import subprocess

# from utils import utils_file


def missing_device_log(missing_list, ip, note):
    entry = str(ip) + "  -  " + str(note)

    if entry not in missing_list:
        missing_list.append(entry)

    return missing_list


def conn_netmiko(miss_dev, dev_cls, mgt_ip, unm, upw, epw):
    dev_cn = ""
    try_tel = False
    lgin_suc = False

    if "telnet" in dev_cls:
        prot = "Telnet"
    else:
        prot = "SSH"

    try:
        dev_cn = netmiko.ConnectHandler(
            device_type=dev_cls, ip=mgt_ip, username=unm, password=upw, secret=epw
        )
        lgin_suc = True

    except netmiko.NetMikoAuthenticationException:
        print(
            "\tNetMikoAuthenticationException: Device failed {} Authentication with username {}".format(
                prot, unm
            )
        )
        miss_dev = missing_device_log(miss_dev, mgt_ip, "Failed Authentication")
        lgin_suc = False

    except (EOFError, netmiko.NetMikoTimeoutException):
        print("\tSSH is not enabled for this device.")
        miss_dev = missing_device_log(miss_dev, mgt_ip, "Failed SSH")
        lgin_suc = False
        try_tel = True

    except Exception as e:
        print(
            "\tGeneral Exception: ERROR!:"
            + str(sys.exc_info()[0])
            + "==>"
            + str(sys.exc_info()[1])
        )
        print(str(e))
        miss_dev = missing_device_log(miss_dev, mgt_ip, "General Exception")
        lgin_suc = False

    return dev_cn, lgin_suc, miss_dev, try_tel


def conn_in_enable(dev_conn):
    # Check to see if login has resulted in enable mode (i.e. priv level 15)
    is_enabled = dev_conn.check_enable_mode()
    # print("is enabled = {}".format(is_enabled))

    if not is_enabled:
        try:
            dev_conn.enable()
            en_success = True
        except Exception as e:
            print(str(e))
            print("\tCannot enter enter enable mode on device!")
            en_success = False

    else:
        print("\tDevice already in enabled mode!")
        en_success = True

    return en_success


def send_netmiko_commands(
    conn, filelist, hostnm, cmds, method, find_file_bool, cfgmode_bool
):
    """
    Function to send commands via a netmiko connection
    :param conn: existing netmiko connection passed to function
    :param filelist: either a list of valid files if find_file_bool is True or a single configuration file if find_file_bool is false
    :param hostnm: hostname of device used to find the configuration file which should contain the hostname
    :param cmds: if method is "command" this is a list of commands, if method is "from_file" this should be empty
    :param method: "command" if the connections is going to use the command method, "from_file"  if using the file
    method - this option uses the filelist information
    :param find_file_bool:
        True if the function should try to find the corresponding configuration file based on hostname
        False if passing a specific configuration file into filelist
    :param cfgmode_bool:
        True if connection should be in config mode - used for configuring device
        False if connection should NOT be in config mode - used for show commands
    :return: output of the selected netmiko command

    """

    cfgoutput = ""
    file_for_host = ""
    is_valid_file = True

    # if find_file is True then filelist is a list of files and we need to iterate through that list to find a file
    # that contains the hostname.  That will be the configuration file
    if find_file_bool:
        for config_file in filelist:
            if hostnm in config_file:
                file_for_host = config_file

    # if find_file is False then filelist is a complete configuration file (with path) only used if method = from_file
    else:
        file_for_host = filelist

    if not conn.check_config_mode() and cfgmode_bool:
        conn.config_mode()

    if cfgmode_bool:
        if conn.check_config_mode():
            if method == "from_file":
                if os.path.isfile(file_for_host):
                    cfgoutput = conn.send_config_from_file(file_for_host)
                    print("\tApplying configuration from file {}".format(file_for_host))
                else:
                    is_valid_file = False

            elif method == "command":
                for cmd in cmds:
                    cfgoutput += conn.send_command(
                        cmd, strip_prompt=False, strip_command=False
                    )
    else:
        if method == "from_file":
            if os.path.isfile(file_for_host):
                cfgoutput = conn.send_config_from_file(file_for_host)
                print("\tApplying commands from file {}".format(file_for_host))
            else:
                is_valid_file = False

        elif method == "command":
            for cmd in cmds:
                cfgoutput += conn.send_command(
                    cmd, strip_prompt=False, strip_command=False
                )

    # If is_valid_file is False then its not a valid file
    if not is_valid_file:
        # File not found
        if file_for_host:
            cfgoutput = "FalseFile: " + file_for_host
        else:
            cfgoutput = (
                "FalseFile: No such file exists. Please check location and name."
            )

    return cfgoutput


def ping_device(ip, debug=False):
    # TODO: Fix This is a duplicate function in utils_logical_networking

    pings = False

    local_os = utils_file.os_is()

    ## Ping with -c 3 on Linux or -n 3 on windows
    if local_os == "linux":
        ping_count = "-c"
        timeout = "-t"
    else:
        ping_count = "-n"
        timeout = "-w"

    device_pings = False
    # info = subprocess.STARTUPINFO()
    # output = subprocess.Popen(['ping', ping_count, '3', '-w', '500', ip], stdout=subprocess.PIPE,
    #                          startupinfo=info).communicate()[0]
    output = subprocess.Popen(
        ["ping", ping_count, "3", timeout, "1000", ip], stdout=subprocess.PIPE
    ).communicate()[0]

    if debug:
        # output is bitecode so need to decode to string
        print(output.decode("UTF-8"))

    if "Destination host unreachable" in output.decode("utf-8"):
        print(ip + " is Offline. Destination unreachable.")
        pings = False
    elif "TTL expired in transit" in output.decode("utf-8"):
        print(ip + " is not reachable. TTL expired in transit.")
        pings = False
    elif "Request timed out" in output.decode("utf-8"):
        print("\n" + ip + " is Offline. Request timed out.")
        pings = False
    elif "Request timeout" in output.decode("utf-8"):
        print("\n" + ip + " is Offline. Request timed out.")
        pings = False
    else:
        pings = True

    return pings


def main():
    pass


# Standard call to the main() function.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script Description", epilog="Usage: ' python utils_netmiko' "
    )

    # parser.add_argument('all', help='Execute all exercises in week 4 assignment')
    parser.add_argument(
        "-a",
        "--all",
        help="Execute all exercises in week 4 assignment",
        action="store_true",
        default=False,
    )
    arguments = parser.parse_args()
    main()
