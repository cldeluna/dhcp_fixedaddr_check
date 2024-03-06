#!/usr/bin/python -tt
# Project: dhcp_fixedaddr_check
# Filename: dhcp_fixedaddr_check.py
# claudiadeluna
# PyCharm

from __future__ import absolute_import, division, print_function

__author__ = "Claudia de Luna (claudia@indigowire.net)"
__version__ = ": 1.0 $"
__date__ = "3/2/24"
__copyright__ = "Copyright (c) 2023 Claudia"
__license__ = "Python"

import argparse
import pandas as pd
import re
import netaddr
from netaddr import *
import utils_netmiko
import time

from netmiko import ConnectHandler


def get_oui(mac):
    """
    Get OUT from netaddr....good if you don't have internet access.
    :param mac:
    :return:
    """
    # print(mac)
    # print(type(mac))

    try:
        maco = netaddr.EUI(mac)
        macf = maco.oui.registration().org
    except netaddr.core.NotRegisteredError:

        macf = "Not available"
    except netaddr.core.AddrFormatError:
        macf = "00:00:00:00:00:00"
        # print(f"Incomplete")

    # print("macf is {}".format(macf))
    return macf


def get_switch():
    sw = ""
    sw = input("Enter switch FQDN or IP: ")
    return sw


def get_data(excel_fil="DemoDataPPB_Standalone.xlsx"):

    try:
        df = pd.read_excel(excel_fil, sheet_name="SiteDeviceData")
    except OSError as e:
        df = pd.DataFrame()
        print(e)

    return df


def search_svi(netmiko_response_list, vlan):
    svi_exists_dict = dict()
    svi_exists_bool = False
    for line_dict in netmiko_response_list:
        if re.search(vlan, line_dict["interface"]):
            svi_exists_dict = line_dict
            svi_exists_bool = True

    return svi_exists_bool, svi_exists_dict


def main():

    df = get_data()

    cols_of_interest = [
        'Site_ID', 'Outage_Window_Date', 'Outage_Window_TimeZone',
        'Outage_Window_StartTime', 'Value_Stream',
        'OT_Decision', 'Notes', 'VRF', 'Current_Device_IP',
        'Device_FQDN', 'Device_MAC', 'Device_VendorOUI', 'Current_Vlan', 'Switch_FQDN',
        'Switch_Port', 'New_Vlan', 'New_Device_IP', 'IPAddressing_Method', 'Manual_DNS_Registration_Required',
        'Manual_FQDN'
    ]

    ppbdf = df[df["IPAddressing_Method"] == "DHCP_Reservation"]

    print(f"\n======================== PPB Rows with Reservations ========================")
    print(ppbdf[cols_of_interest])
    print(f"============================================================================\n")
    missing_dev_list = list()

    for index in range(len(ppbdf)):

        sw = ppbdf["Switch_FQDN"].loc[index]
        vlan = str(ppbdf["New_Vlan"].loc[index])
        mac = ppbdf["Device_MAC"].loc[index]
        # New_Device_IP
        new_ip = str(ppbdf["New_Device_IP"].loc[index]).strip()
        mac_obj = EUI(mac, dialect=netaddr.mac_cisco)
        oui = get_oui(mac)

        print(
            f"\n** switch {sw}, MAC {mac_obj}, Vendor OUI {oui} and new vlan {vlan}\n"
        )

        # cisco1 = {
        #     "device_type": "cisco_xe",
        #     "host": sw,
        #     "username": "cisco",
        #     "password": "cisco",
        # }

        conn_obj, login_success, baddev_list, try_telnet = utils_netmiko.conn_netmiko(
            missing_dev_list, "cisco_xe", sw, "cisco", "cisco", "cisco"
        )
        # conn_obj, login_success, baddev_list, try_telnet = utils_netmiko.conn_netmiko(
        #     missing_dev_list, "cisco_xe", sw, "cs", "cdfo", "cdo"
        # )
        if login_success:
            print(f"\nOK! Login to {sw} succeeded!")
        else:
            print(f"\nERROR! Login to {sw} failed!")

        cmd = f"show ip int br | i {vlan}"
        # with ConnectHandler(**cisco1) as conn_obj:
        result = conn_obj.send_command(cmd)
        result2 = conn_obj.send_command("show ip interface brief", use_textfsm=True)
        # result = conn_obj.send_command(cmd)

        # print(f"result type is {")
        # print(result)
        # print(result2)
        # print(len(result2))

        svi_bool, svi_list = search_svi(result2, vlan)
        # print(f"svi boolean {svi_bool} svi list of dicts {svi_list}")

        if svi_bool:
            print(f"\nError! there is already an SVI for Vlan {vlan}")
            exit("Aborting run")
        else:
            print(f"\nOK! No SVI exists for Vlan {vlan}. Its safe to proceed.")

            try:
                print("Entering enable mode")
                conn_obj.enable()

                config_set_list = list()
                config_set_list.append(f"interface Vlan{vlan}")
                config_set_list.append(f" mac-address {mac_obj}")
                config_set_list.append(f" ip address dhcp")
                config_set_list.append(" no shut")

                cfg_res = conn_obj.send_config_set(config_set_list)
                print(f"\nConfiguration payload sent to {sw}:")
                print(cfg_res)
                secs_to_wait_for_lease = 11
                print(f"Waiting {secs_to_wait_for_lease} seconds for a DHCP lease...")
                time.sleep(secs_to_wait_for_lease)
                result_check_svi = conn_obj.send_command(
                    "show ip interface brief", use_textfsm=True
                )
                # print(result_check_svi)

                post_svi_bool, post_svi_dict = search_svi(result_check_svi, vlan)
                print(post_svi_dict)
                print(post_svi_bool)

                if post_svi_dict:
                    if new_ip == post_svi_dict["ip_address"]:
                        print(
                            f"\n!!!!!! DHCP Reservation GOOD!\n"
                            f"MAC Address {mac} should have IP {new_ip} according to PPB "
                            f"and has IP {post_svi_dict['ip_address']}.\n"
                        )
                    else:
                        print(
                            f"\n!!!!!! DHCP Reservation BAD!\n"
                            f"MAC Address {mac} should have IP {new_ip} according to PPB "
                            f"but has {post_svi_dict['ip_address']}.\n"
                        )

                # Check that interface is configured for DHCP
                print(f"\nConfirming {vlan} SVI is configured for dhcp, otherwise will not remove!\n")
                result = conn_obj.send_command(f"show run int Vlan{vlan}")

                if "ip address dhcp" in result:
                    ok_to_remove_svi = True
                else:
                    ok_to_remove_svi = False

                if ok_to_remove_svi:
                    time.sleep(1)
                    print("\nSVI configuration as expected.  Removing SVI.")
                    back_out_list = [f"no interface Vlan{vlan}"]
                    cfg_res = conn_obj.send_config_set(back_out_list)
                    print(f"\nConfiguration payload sent to {sw}:")
                    print(cfg_res)
                else:
                    print("\nSVI configuration not as expected.  Will not remove SVI.")
                    print(result)

            except Exception as e:
                print("Failed to go into enable mode")


# Standard call to the main() function.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Script Description",
        epilog="Usage: ' python dhcp_fixedaddr_check.py' ",
    )

    # parser.add_argument('all', help='Execute all exercises in week 4 assignment')
    # parser.add_argument('-a', '--all', help='Execute all exercises in week 4 assignment', action='store_true',default=False)
    arguments = parser.parse_args()
    main()
