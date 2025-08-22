# -*- coding: utf-8 -*-
# Copyright 2018 Jasper Lievisse Adriaanse. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for Cisco S350 devices.

Read https://napalm.readthedocs.io for more information.
"""

from __future__ import print_function
from __future__ import unicode_literals

import netaddr
import re
import socket

from netmiko import ConnectHandler
from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    CommandErrorException,
    ConnectionClosedException,
)
from napalm.base.helpers import canonical_interface_name
from napalm.base.netmiko_helpers import netmiko_args

import napalm.base.constants as C
import napalm.base.canonical_map

from typing import List


class S350Driver(NetworkDriver):
    """Napalm driver for S350."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Constructor."""
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        if optional_args is None:
            optional_args = {}

        self._dest_file_system = optional_args.get("dest_file_system", None)

        # Netmiko possible arguments
        self.netmiko_optional_args = netmiko_args(optional_args)

        self.platform = "s350"
        self.port = optional_args.get("port", 22)
        self.device = None
        self.force_no_enable = optional_args.get("force_no_enable", False)

    def open(self):
        """Open a connection to the device."""

        self.device = ConnectHandler(
            device_type="cisco_s300",
            host=self.hostname,
            username=self.username,
            password=self.password,
            **self.netmiko_optional_args,
        )
        if not self.force_no_enable:
            self.device.enable()

    def _discover_file_system(self):
        try:
            return self.device._autodetect_fs()
        except Exception:
            msg = (
                "Netmiko _autodetect_fs failed (to work around specify "
                "dest_file_system in optional_args)."
            )
            raise CommandErrorException(msg)

    def close(self):
        """Close the connection to the device."""
        self.device.disconnect()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd, read_timeout=self.timeout)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command, read_timeout=self.timeout)
            return output.strip()
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def _parse_uptime(self, uptime_str):
        """Parse an uptime string into number of seconds"""
        uptime_str = uptime_str.strip()
        days, timespec = uptime_str.split(",")

        hours, minutes, seconds = timespec.split(":")

        uptime_sec = (int(days) * 86400) + (int(hours) * 3600) + (int(minutes) * 60) + int(seconds)
        return uptime_sec

    def get_arp_table(self, vrf=""):
        """
        Get the ARP table, the age isn't readily available so we leave that out for now.

        vrf is needed for test - no support on s350
        """

        arp_table = []

        output = self._send_command("show arp")

        for line in output.splitlines():
            # A VLAN may not be set for the entry
            if "vlan" not in line:
                continue
            if len(line.split()) == 4:
                interface, ip, mac, _ = line.split()
            elif len(line.split()) == 5:
                if1, if2, ip, mac, _ = line.split()
                interface = "{} {}".format(if1, if2)
            elif len(line.split()) == 6:
                _, _, interface, ip, mac, _ = line.split()
            else:
                raise ValueError("Unexpected output: {}".format(line.split()))

            interface = canonical_interface_name(interface)

            entry = {
                "interface": interface,
                "mac": napalm.base.helpers.mac(mac),
                "ip": ip,
                "age": 0.0,
            }

            arp_table.append(entry)

        return arp_table

    def get_config(
        self,
        retrieve="all",
        full=False,
        sanitized=False,
        format: str = "text",
    ):
        """
        get_config for S350. Since this firmware doesn't support a candidate
        configuration we leave it empty.
        """

        configs = {
            "startup": "",
            "running": "",
            "candidate": "",
        }

        if retrieve in ("all", "startup"):
            startup = self._send_command("show startup-config")
            configs["startup"] = self._get_config_filter(startup)

        if retrieve in ("all", "running"):
            # IOS supports "full" only on "show running-config"
            run_full = " detailed" if full else ""
            running = self._send_command("show running-config" + run_full)
            configs["running"] = self._get_config_filter(running)

        if sanitized:
            configs = self._get_config_sanitized(configs)

        return configs

    def _get_config_filter(self, config):
        # The output of get_config should be directly usable by load_replace_candidate()

        # remove header
        filter_strings = [
            r"(?sm)^config-file-header.*^@$",
        ]

        for ft in filter_strings:
            config = re.sub(ft, "", config)

        return config

    def _get_config_sanitized(self, configs):
        # Do not output sensitive information

        # use Cisco IOS filters
        configs = napalm.base.helpers.sanitize_configs(configs, C.CISCO_SANITIZE_FILTERS)

        # defina my own filters
        s350_filters = {
            r"^(.* password) (\S+) (\S+) (.*)$": r"\1 \2 <removed> \4",
            r"^(snmp-server location) (\S+).*$": r"\1 <removed>",
        }

        configs = napalm.base.helpers.sanitize_configs(configs, s350_filters)

        return configs

    def get_facts(self):
        """
        Return NAPALM facts with a correct interface_list that includes SVIs
        with static IPv4s. All fields have safe defaults (no None).
        """
        facts = {
            "vendor": "Cisco",
            "model": "",
            "hostname": "",
            "fqdn": "",
            "os_version": "",
            "serial_number": "",
            "uptime": 0,
            "interface_list": [],
        }

        """Return a set of facts from the device."""
        serial_number, fqdn, os_version, hostname, domainname = ("Unknown",) * 5

        # Submit commands to the device.
        show_ver = self._send_command("show version")
        show_sys = self._send_command("show system")
        show_inv = self._send_command("show inventory")
        show_hosts = self._send_command("show hosts")
        show_int_st = self._send_command("show interfaces status")

        os_version = self._get_facts_parse_os_version(show_ver)

        # hostname
        hostname = self._get_facts_hostname(show_sys)
        # special case for SG500 fw v1.4.x
        if hostname == "Unknown":
            hostname = self._get_facts_hostname_from_config(
                self._send_command("show running-config")
            )

        # uptime
        uptime_str = self._get_facts_uptime(show_sys)
        uptime = self._parse_uptime(uptime_str)

        # serial_number and model
        # take first device
        inventory = self._get_facts_parse_inventory(show_inv)["1"]
        serial_number = inventory["sn"]
        model = inventory["pid"]

        # fqdn
        # take first domain name
        domainname = "Unknown"
        atDTh = False
        atDT = False
        for line in show_hosts.splitlines():
            if line.startswith("Default Domain Table"):
                atDTh = True
                continue
            if atDTh and line.startswith("--------"):
                atDT = True
                continue
            if atDT:
                fields = line.split(" ")
                domainname = fields[0]
                break

        if domainname == "Domain":
            domainname = "Unknown"
        if domainname != "Unknown" and hostname != "Unknown":
            fqdn = "{0}.{1}".format(hostname, domainname)

        # ---- hostname/model/os/serial/uptime (best-effort) ----
        facts["fqdn"] = str(fqdn)
        facts["hostname"] = str(hostname)
        facts["model"] = str(model)
        facts["serial_number"] = str(serial_number)
        facts["os_version"] = str(os_version)
        facts["uptime"] = float(uptime)

        # ---- Build interface_list from "show interfaces status" ----
        # NEW: merge SVIs that have a static IPv4 configured
        try:
            run_conf = self._send_command("show running-config")
        except Exception:
            run_conf = ""
        interfaces = []
        try:
            show_int_st = self._send_command("show interfaces status")
        except Exception:
            show_int_st = ""

        if show_int_st:
            show_int_st = show_int_st.strip()
            # remove the header information (your existing pattern)
            show_int_st = re.sub(
                r"(^-.*$|^Port .*$|^Ch .*$)|^\s.*$|^.*Flow.*$", "", show_int_st, flags=re.M
            )
            # NEW: drop any residual device prompts like "HOSTNAME#" or "HOSTNAME>"
            show_int_st = re.sub(r"(?m)^[^\n]*[>#]\s*$", "", show_int_st)
            for line in filter(None, (ln.strip() for ln in show_int_st.splitlines())):
                cols = re.split(r"\s{2,}|\t+", line)
                if not cols:
                    continue
                port = cols[0].strip()
                if port and not port.lower().startswith(("port", "ch")):
                    interfaces.append(port)

        # ---- Pre-scan SVIs WITH static IPs and merge to interface_list ----
        svi_candidates = []
        if run_conf:
            for m in re.finditer(r"(?mis)^interface\s+vlan\s+(\d+)(.*?)(?=^\S|\Z)", run_conf):
                vlan_id, body = m.groups()
                if re.search(
                    r"(?mi)^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+(?!\s+dhcp)",
                    body,
                ):
                    svi_candidates.append(f"Vlan{vlan_id}")

        # Normalize VLAN names already in list, add missing SVI candidates, dedupe
        interfaces = [re.sub(r"(?i)^vlan\s*(\d+)$", r"Vlan\1", name) for name in interfaces]
        for svi in svi_candidates:
            if svi not in interfaces:
                interfaces.append(svi)

        # NEW: normalize names, drop prompts/empties, canonicalize, and dedupe
        cleaned: List[str] = []
        seen = set()
        for name in interfaces:
            if not name:
                continue
            # Skip any prompt-like leftovers defensively
            if re.match(r"^[A-Za-z0-9_.:-]+[>#]$", name):
                continue
            n = name.strip()
            # Normalize "Vlan 1200" -> "Vlan1200"
            n = re.sub(r"(?i)^vlan\s*(\d+)$", r"Vlan\1", n)
            try:
                n = canonical_interface_name(n)
            except Exception:
                pass
            if n not in seen:
                seen.add(n)
                cleaned.append(n)
        interfaces = cleaned


        # NEW: merge SVIs that have a static IPv4 configured
        try:
            run_conf = self._send_command("show running-config")
        except Exception:
            run_conf = ""

        if run_conf:
            for m in re.finditer(r"(?mis)^interface\s+vlan\s+(\d+)(.*?)(?=^\S|\Z)", run_conf):
                vlan_id, body = m.groups()
                # include ONLY if static ipv4 present (skip DHCP/unconfigured)
                if not re.search(
                    r"(?mi)^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+(?!\s+dhcp)",
                    body,
                ):
                    continue
                svi = f"Vlan{vlan_id}"
                if svi not in interfaces:
                    interfaces.append(svi)

        facts["interface_list"] = interfaces

        # Final sanitize: ensure no None anywhere in facts
        for k, v in list(facts.items()):
            if v is None:
                facts[k] = "" if k in ("vendor", "model", "hostname", "fqdn", "os_version", "serial_number") else 0

        return facts


    def _get_facts_hostname_from_config(self, show_running):
        # special case for SG500 fw v1.4.x
        hostname = "Unknown"
        for line in show_running.splitlines():
            if line.startswith("hostname "):
                _, hostname = line.split("hostname")
                hostname = hostname.strip()
                break

        return hostname

    def _get_facts_hostname(self, show_sys):
        hostname = "Unknown"
        for line in show_sys.splitlines():
            if line.startswith("System Name:"):
                _, hostname = line.split("System Name:")
                hostname = hostname.strip()
                break

        return hostname

    def _get_facts_uptime(self, show_sys):
        i = 0
        syslines = []
        fields = []
        uptime_header_lineNo = None
        uptime_str = None
        for line in show_sys.splitlines():
            # All models except SG500 fw 1.4.x
            if line.startswith("System Up Time (days,hour:min:sec):"):
                _, uptime_str = line.split("System Up Time (days,hour:min:sec):")
                break

            line = re.sub(r"  *", " ", line, re.M)
            line = line.strip()

            fields = line.split(" ")
            syslines.append(fields)

            if "Unit" in syslines[i] and "time" in syslines[i]:
                uptime_header_lineNo = i

            i += 1

        # SG500 fw 1.4.x
        if not uptime_str:
            uptime_str = syslines[uptime_header_lineNo + 2][1]

        return uptime_str

    def _get_facts_parse_inventory(self, show_inventory):
        """inventory can list more modules/devices"""
        # make 1 module 1 line
        show_inventory = re.sub(r"\nPID", "  PID", show_inventory, re.M)
        # delete empty lines
        show_inventory = re.sub(r"^\n", "", show_inventory, re.M)
        show_inventory = re.sub(r"\n\n", "", show_inventory, re.M)
        show_inventory = re.sub(r"\n\s*\n", r"\n", show_inventory, re.M)
        lines = show_inventory.splitlines()

        modules = {}
        for line in lines:
            match = re.search(
                r"""
                ^
                NAME:\s"(?P<name>\S+)"\s*
                DESCR:\s"(?P<descr>[^"]+)"\s*
                PID:\s(?P<pid>\S+)\s*
                VID:\s(?P<vid>.+\S)\s*
                SN:\s(?P<sn>\S+)\s*
                """,
                line,
                re.X,
            )
            module = match.groupdict()
            modules[module["name"]] = module

        if modules:
            return modules

    def _get_facts_parse_os_version(self, show_ver):
        # os_version
        # detect os ver > 2
        if re.search(r"^Active-image", show_ver):
            for line in show_ver.splitlines():
                # First version line is the active version
                if re.search(r"Version:", line):
                    _, os_version = line.split("Version: ")
                    break
        elif re.search(r"^SW version", show_ver):
            for line in show_ver.splitlines():
                if re.search(r"^SW version", line):
                    _, ver = line.split("    ")
                    os_version, _ = ver.split(" (")
                    break
        else:
            # show_ver = re.sub(r'^\n', '', show_ver, re.M)
            for line in show_ver.splitlines():
                line = re.sub(r"  *", " ", line, re.M)
                line = line.strip()
                line_comps = line.split(" ")
                if line_comps[0] == "1":
                    os_version = line_comps[1]
                    break

        return os_version

    def get_interfaces(self):
        """
        Return a dict keyed by interface name with attributes:
        is_up, is_enabled, description, mac_address, speed, mtu, last_flapped.
        Includes ONLY VLAN SVIs that have a static IPv4 configured.
        Never returns None for any field.
        """
        interfaces = {}

        # ---- Physical/logical ports from "show interfaces status" (best-effort) ----
        try:
            show_status_output = self._send_command("show interfaces status")
        except Exception:
            show_status_output = ""

        try:
            show_description_output = self._send_command("show interfaces description")
        except Exception:
            show_description_output = ""

        # MTU (SG/CBS variants expose jumbo setting via this command)
        try:
            show_jumbo_frame = self._send_command("show ports jumbo-frame")
            mtu = 9000 if re.search(r"Jumbo frames are enabled", show_jumbo_frame, re.M) else 1518
        except Exception:
            mtu = 1518

        mac_cache = ""

        for status_line in show_status_output.splitlines():
            if "Up" not in status_line and "Down" not in status_line:
                continue

            # Some firmwares shorten Po* lines
            if "Po" in status_line:
                try:
                    interface, _, _, speed, _, _, link_state = status_line.split()
                except ValueError:
                    continue
            else:
                try:
                    interface, _, _, speed, _, _, link_state, _, _ = status_line.split()
                except ValueError:
                    continue

            # Retrieve a chassis/port MAC once; many CBS share same local MAC across ports
            if not mac_cache:
                try:
                    show_system_output = self._send_command("show lldp local " + interface)
                    # Typical first line: "Local Port ID: 70:10:6F:AA:BB:CC"
                    first = show_system_output.splitlines()[0]
                    mac_cache = first.split(":", maxsplit=1)[1].strip()
                except Exception:
                    mac_cache = ""

            if speed == "--":
                is_enabled = False
                speed_val = 0
            else:
                is_enabled = True
                try:
                    speed_val = int(speed)
                except Exception:
                    msp = re.search(r"(\d+)", speed)
                    speed_val = int(msp.group(1)) if msp else 0

            is_up = (link_state == "Up")

            # description (from "show interfaces description")
            description = ""
            for descr_line in show_description_output.splitlines():
                if descr_line.startswith(interface):
                    parts = descr_line.split()
                    if len(parts) > 1:
                        description = " ".join(parts[1:])
                    break

            entry = {
                "is_up": bool(is_up),
                "is_enabled": bool(is_enabled),
                "speed": float(speed_val),
                "mtu": mtu,
                "last_flapped": 0.0,
                "description": description or "",
                "mac_address": (mac_cache or ""),
            }

            interface = canonical_interface_name(interface)
            interfaces[interface] = entry

        # ---- Supplement VLAN SVIs from running-config (ONLY those with static IPv4) ----
        try:
            run_conf = self._send_command("show running-config")
        except Exception:
            run_conf = ""

        if run_conf:
            for m in re.finditer(r"(?mis)^interface\s+vlan\s+(\d+)(.*?)(?=^\S|\Z)", run_conf):
                vlan_id, body = m.groups()
                # Only include if static IPv4 configured (skip DHCP-only/unconfigured)
                if not re.search(
                    r"(?mi)^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+(?!\s+dhcp)",
                    body,
                ):
                    continue

                iface = f"Vlan{vlan_id}"
                admin_up = not re.search(r"(?mi)^\s*shutdown\b", body)
                d_m = re.search(r"(?mi)^\s*name\s+(.+)$", body)
                desc = d_m.group(1).strip() if d_m else ""

                if iface not in interfaces:
                    interfaces[iface] = {
                        "is_up": bool(admin_up),
                        "is_enabled": bool(admin_up),
                        "speed": float(0),
                        "mtu": mtu,
                        "last_flapped": 0.0,
                        "description": desc,
                        "mac_address": "",
                    }
                else:
                    # sanitize/enrich
                    if interfaces[iface].get("description") in (None, 0):
                        interfaces[iface]["description"] = desc or ""
                    if interfaces[iface].get("mac_address") is None:
                        interfaces[iface]["mac_address"] = ""
                    if interfaces[iface].get("speed") is None:
                        interfaces[iface]["speed"] = float(0)
                    if interfaces[iface].get("last_flapped") is None:
                        interfaces[iface]["last_flapped"] = 0.0

        # Final sanitize: ensure no None values
        for _if, _d in interfaces.items():
            if _d.get("description") is None:
                _d["description"] = ""
            if _d.get("mac_address") is None:
                _d["mac_address"] = ""
            if _d.get("speed") is None:
                _d["speed"] = float(0)
            if _d.get("last_flapped") is None:
                _d["last_flapped"] = 0.0

        return interfaces


    def get_interfaces_ip(self):
        """
        Returns all configured interface IP addresses.
        Normalizes SVI names to Vlan<ID>.
        Ignores 'unassigned' and DHCP-only SVIs.
        Builds prefix from mask when split across columns.
        """
        interfaces = {}

        # Helper to add IPv4 safely
        def _add_ipv4(ifname, ip, mask):
            if not ifname or not ip or not mask:
                return
            if re.match(r"(?i)^vlan\s*\d+$", ifname):
                ifname = re.sub(r"(?i)^vlan\s*(\d+)$", r"Vlan\1", ifname)
            try:
                net = netaddr.IPNetwork(f"{ip}/{mask}")
            except Exception:
                return
            fam = f"ipv{net.version}"
            interfaces.setdefault(ifname, {}).setdefault(fam, {})
            interfaces[ifname][fam].setdefault(str(net.ip), {"prefix_length": net.prefixlen})

        # Parse concise/brief table if available
        try:
            show_ip_int = self._send_command("show ip interface")
        except Exception:
            show_ip_int = ""

        # Also grab running-config for masks (and fallback)
        try:
            run_conf = self._send_command("show running-config")
        except Exception:
            run_conf = ""

        # Build mask index from running-config
        masks_by_if = {}
        if run_conf:
            for m in re.finditer(r"(?mis)^interface\s+(\S+\s*\d+)(.*?)(?=^\S|\Z)", run_conf):
                ifname_raw, body = m.groups()
                ifname = ifname_raw.strip()
                if re.match(r"(?i)^vlan\s*\d+$", ifname):
                    ifname = re.sub(r"(?i)^vlan\s*(\d+)$", r"Vlan\1", ifname)
                ipm = re.search(
                    r"(?mi)^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?!\s+dhcp)",
                    body,
                )
                if ipm:
                    masks_by_if[ifname] = ipm.groups()

        # Parse the table-style output using existing helpers (fields_end & line_to_fields)
        if show_ip_int:
            header = True
            for line in show_ip_int.splitlines():
                if header:
                    if re.match(r"^---+ -+ .*$", line):
                        header = False
                        fields_end = self._get_ip_int_fields_end(line)
                    continue

                if re.match(r"^---+ -+ .*$", line):
                    break

                line_elems = self._get_ip_int_line_to_fields(line, fields_end)
                # Only 'Valid' rows (firmware dependent; last column is status)
                if line_elems[len(line_elems) - 1] != "Valid":
                    continue

                cidr = line_elems[0]
                ifname = line_elems[1]

                # Skip unassigned
                if isinstance(cidr, str) and cidr.lower() == "unassigned":
                    continue

                # Normalize VLAN name
                if re.match(r"(?i)^vlan\s*\d+$", ifname):
                    ifname = re.sub(r"(?i)^vlan\s*(\d+)$", r"Vlan\1", ifname)

                # If no '/', try to locate a dotted netmask among the parsed fields
                mask = None
                if "/" not in cidr:
                    for idx, val in line_elems.items():
                        if idx in (0, len(line_elems) - 1):
                            continue  # skip IP and Status
                        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val):
                            mask = val
                            break
                    if mask:
                        ip_only = cidr
                        _add_ipv4(ifname, ip_only, mask)
                        continue
                    # Fall back to running-config mask index if same IP found there
                    if ifname in masks_by_if and masks_by_if[ifname][0] == cidr:
                        _add_ipv4(ifname, masks_by_if[ifname][0], masks_by_if[ifname][1])
                        continue

                # If CIDR contains '/', try to parse directly
                try:
                    ipnet = netaddr.IPNetwork(cidr)
                    fam = f"ipv{ipnet.version}"
                    interfaces.setdefault(ifname, {}).setdefault(fam, {})
                    interfaces[ifname][fam].setdefault(str(ipnet.ip), {"prefix_length": ipnet.prefixlen})
                except Exception:
                    pass  # ignore malformed lines

        # Fallback/supplement: add SVI static IPv4s from running-config
        if run_conf:
            for m in re.finditer(r"(?mis)^interface\s+vlan\s+(\d+)(.*?)(?=^\S|\Z)", run_conf):
                vlan_id, body = m.groups()
                ipm = re.search(
                    r"(?mi)^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?!\s+dhcp)",
                    body,
                )
                if not ipm:
                    continue
                ipaddr, mask = ipm.groups()
                _add_ipv4(f"Vlan{vlan_id}", ipaddr, mask)

        return interfaces



    # Get VLANS
    def get_vlans(self):
        """
        Return VLAN dict keyed by VLAN ID:
        { 1200: { "name": "MGMT_n", "interfaces": ["GigabitEthernet1/0/1", ...] }, ... }
        Robust against platform differences; returns {} on parse/command failure.
        """
        vlans: Dict[int, Dict[str, Any]] = {}
        try:
            out = self._send_command("show vlan brief")
        except Exception:
            try:
                out = self._send_command("show vlan")
            except Exception:
                return {}  # fail safe

        try:
            # Typical CBS output has lines like:
            # "1200   MGMT_n      Active    Gi1/0/1,Gi1/0/2"
            for line in out.splitlines():
                line = line.strip()
                m = re.match(r'^(\d+)\s+(\S+)\s+\S+(?:\s+|$)(.*)$', line)
                if not m:
                    continue
                vid, name, ports = m.groups()
                vid = int(vid)
                # normalize port list (optional; empty list if none)
                if ports and not ports.lower().startswith("po"):
                    ifaces = [p.strip() for p in re.split(r'[,\s]+', ports) if p.strip()]
                else:
                    ifaces = []
                vlans[vid] = {"name": name, "interfaces": ifaces}
        except Exception:
            # If parsing fails, don't break discovery
            return {}

        return vlans

    def _get_ip_int_line_to_fields(self, line, fields_end):
        """dynamic fields lenghts"""
        line_elems = {}
        index = 0
        f_start = 0
        for f_end in fields_end:
            line_elems[index] = line[f_start:f_end].strip()
            index += 1
            f_start = f_end
        return line_elems

    def _get_ip_int_fields_end(self, dashline):
        """fields length are diferent device to device, detect them on horizontal line"""

        fields_end = [m.start() for m in re.finditer(" ", dashline.strip())]
        # fields_position.insert(0,0)
        fields_end.append(len(dashline))

        return fields_end

    def get_lldp_neighbors(self):
        """get_lldp_neighbors implementation for s350"""
        neighbors = {}
        output = self._send_command("show lldp neighbors")

        header = True  # cycle trought header
        local_port = ""  # keep previous context - multiline syname
        remote_port = ""
        remote_name = ""
        for line in output.splitlines():
            if header:
                # last line of header
                match = re.match(r"^--------- -+ .*$", line)
                if match:
                    header = False
                    fields_end = self._get_lldp_neighbors_fields_end(line)
                continue

            line_elems = self._get_lldp_neighbors_line_to_fields(line, fields_end)

            # info owerflow to the other line
            if line_elems[0] == "" or line_elems[4] == "" or line_elems[5] == "":
                # complete owerflown fields
                local_port = local_port + line_elems[0]
                remote_port = remote_port + line_elems[2]
                remote_name = remote_name + line_elems[3]
                # then reuse old values na rewrite previous entry
            else:
                local_port = line_elems[0]
                remote_port = line_elems[2]
                remote_name = line_elems[3]

            local_port = canonical_interface_name(local_port)

            neighbor = {
                "hostname": remote_name,
                "port": remote_port,
            }
            neighbor_list = [
                neighbor,
            ]
            neighbors[local_port] = neighbor_list

        return neighbors

    def _get_lldp_neighbors_line_to_fields(self, line, fields_end):
        """dynamic fields lenghts"""
        line_elems = {}
        index = 0
        f_start = 0
        for f_end in fields_end:
            line_elems[index] = line[f_start:f_end].strip()
            index += 1
            f_start = f_end
        return line_elems

    def _get_lldp_neighbors_fields_end(self, dashline):
        """fields length are diferent device to device, detect them on horizontal line"""

        fields_end = [m.start() for m in re.finditer(" ", dashline)]
        fields_end.append(len(dashline))

        return fields_end

    def _get_lldp_line_value(self, line):
        """
        Safe-ish method to get the value from an 'lldp neighbors $IF' line.
        """
        try:
            value = line.split(":")[1:][0].strip()
        except KeyError:
            value = "N/A"

        return value

    def get_lldp_neighbors_detail(self, interface=""):
        """
        get_lldp_neighbors_detail() implementation for s350
        """
        details = {}

        # First determine all interfaces with valid LLDP neighbors
        for local_port in self.get_lldp_neighbors().keys():
            if interface:
                if interface == local_port:
                    entry = self._get_lldp_neighbors_detail_parse(local_port)
                    local_port = canonical_interface_name(local_port)
                    details[local_port] = [
                        entry,
                    ]

            else:
                entry = self._get_lldp_neighbors_detail_parse(local_port)
                local_port = canonical_interface_name(local_port)
                details[local_port] = [
                    entry,
                ]

        return details

    def _get_lldp_neighbors_detail_parse(self, local_port):
        # Set defaults, just in case the remote fails to provide a field.
        (
            remote_port_id,
            remote_port_description,
            remote_chassis_id,
            remote_system_name,
            remote_system_description,
            remote_system_capab,
            remote_system_enable_capab,
        ) = ("N/A",) * 7

        output = self._send_command("show lldp neighbors {}".format(local_port))

        for line in output.splitlines():
            if line.startswith("Port ID"):
                remote_port_id = line.split()[-1]
            elif line.startswith("Device ID"):
                remote_chassis_id = line.split()[-1]
            elif line.startswith("Port description"):
                remote_port_description = self._get_lldp_line_value(line)
            elif line.startswith("System Name"):
                remote_system_name = self._get_lldp_line_value(line)
            elif line.startswith("System description"):
                remote_system_description = self._get_lldp_line_value(line)
            elif line.startswith("Capabilities"):
                caps = self._get_lldp_neighbors_detail_capabilities_parse(line)

        remote_port_id = canonical_interface_name(remote_port_id)

        entry = {
            "parent_interface": "N/A",
            "remote_port": remote_port_id,
            "remote_port_description": remote_port_description,
            "remote_chassis_id": remote_chassis_id,
            "remote_system_name": remote_system_name,
            "remote_system_description": remote_system_description,
            "remote_system_capab": caps,
            "remote_system_enable_capab": caps,
        }

        return entry

    def _get_lldp_neighbors_detail_capabilities_parse(self, line):
        # Only the enabled capabilities are displayed.
        try:
            # Split a line like 'Capabilities: Bridge, Router, Wlan-Access-Point'
            capabilities = line.split(":")[1:][0].split(",")
        except KeyError:
            capabilities = []

        caps = []
        # For all capabilities, except 'Repeater', the shorthand
        # is the first character.
        for cap in capabilities:
            cap = cap.strip()
            if cap == "Repeater":
                caps.append("r")
            else:
                caps.append(cap[0])

        return caps

    def get_ntp_servers(self):
        """Returns NTP servers."""
        ntp_servers = {}
        output = self._send_command("show sntp status")

        servers = re.findall(r"^Server\s*:\s*(\S+)\s*.*$", output, re.M)

        for server in servers:
            ntp_servers[server] = {}

        return ntp_servers

    def is_alive(self):
        """Returns an indication of the state of the connection."""
        null = chr(0)

        if self.device is None:
            return {"is_alive": False}

        # Send a NUL byte to keep the connection alive.
        try:
            self.device.write_channel(null)
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (socket.error, EOFError):
            # If we couldn't send it, the connection is not available.
            return {"is_alive": False}

        # If we made it here, assume the worst.
        return {"is_alive": False}

    @property
    def dest_file_system(self):
        # First ensure we have an open connection.
        if self.device and self._dest_file_system is None:
            self._dest_file_system = self._discover_file_system()
        return self._dest_file_system
