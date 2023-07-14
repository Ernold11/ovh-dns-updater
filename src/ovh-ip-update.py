#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import sys
import time
from logging.handlers import TimedRotatingFileHandler
from typing import Literal

import ovh
import requests
import yaml


class OVHIpUpdate:
    def __init__(self) -> None:
        self.current_ip_file = "/tmp/current_ip.yaml"  # nosec
        self.record_changed = 0
        self.settings = self.load_config()
        self.logger = self.get_logger("/tmp/ovh-dns-updater.log")  # nosec
        self.client = ovh.Client(**self.settings["ovh"])

    def get_logger(self, path):
        logger = logging.getLogger("MAIN")
        logger.setLevel(logging.INFO)

        handler = TimedRotatingFileHandler(
            path, when="d", interval=1, backupCount=5
        )
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)

        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(formatter)

        logger.addHandler(stdout_handler)

        return logger

    def load_config(self):
        conf_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config", "conf.yaml"
        )

        with open(conf_file_path) as conf_file:
            return yaml.safe_load(conf_file)

    def run(self):
        sleep_time_str = os.getenv("SLEEP_TIME") or "300"
        sleep_time = int(sleep_time_str)
        while True:
            self.update_record_if_needed()
            self.log(f"Sleep {sleep_time}s")
            time.sleep(sleep_time)
            self.log("#" * 70)

    def get_current_ip(self, v=4) -> str | Literal[False]:
        if v == 4:
            url_list = [
                "https://api.ipify.org",
                "https://ipv4.lafibre.info/ip.php",
                "https://v4.ident.me",
            ]
        else:
            url_list = [
                "https://api6.ipify.org",
                "https://ipv6.lafibre.info/ip.php",
                "https://v6.ident.me",
            ]
        ip = ""
        message = ""
        for url in url_list:
            try:
                r = requests.get(url, timeout=30.0)
            except requests.exceptions.RequestException as e:
                message += f"failed getting ipv{v} address from {url} because {str(e)} occurred\n"
                continue
            if r.status_code == requests.codes["ok"]:
                ip = r.text
                break

            message += f"Cannot get IPv{v} from {url}: requests.get returned status_code {r.status_code}.\n"
        if ip != "":
            return ip
        elif v in self.settings["ip_versions_required"]:
            message += f"Failed getting required IPv{v}. There is most likely a real connectivity problem. Aborting"
            self.log(message)
            sys.exit()
        else:
            return False

    def log(self, msg) -> None:
        self.logger.info(msg)

    def update_record(self, domain, subdomain, new_ip, _ttl=600) -> None:
        # Update the (A or AAAA) record with the provided IP

        typ = "AAAA" if ":" in new_ip else "A"
        self.log(f"checking record {typ} for {subdomain}.{domain}")
        path = f"/domain/zone/{domain}/record"
        result = self.client.get(path, fieldType=typ, subDomain=subdomain)

        if len(result) != 1:
            # creating NEW record
            result = self.client.post(
                path,
                fieldType=typ,
                subDomain=subdomain,
                target=new_ip,
                ttl=_ttl,
            )
            self.client.post(f"/domain/zone/{domain}/refresh")
            result = self.client.get(path, fieldType=typ, subDomain=subdomain)
            record_id = result[0]
            self.record_changed += 1
            self.log(f"### created new record {typ} for {subdomain}.{domain}")
        else:
            # record exists
            record_id = result[0]
            path = f"/domain/zone/{domain}/record/{record_id}"
            result = self.client.get(path)
            oldip = result["target"].strip()
            self.log(f"record exists, with ip: {oldip}")
            if oldip == new_ip:
                self.log("nothing to do")
                return

            self.log(f"updating to: {new_ip}")
            result = self.client.put(
                path, subDomain=subdomain, target=new_ip, ttl=_ttl
            )
            self.client.post(f"/domain/zone/{domain}/refresh")
            self.record_changed += 1
        # checking changes
        result = self.client.get(f"/domain/zone/{domain}/record/{record_id}")
        if new_ip != result["target"]:
            self.record_changed -= 1
            raise Exception(
                f"Error updating {subdomain}.{domain} with {new_ip}"
            )

    def delete_record(self, domain, subdomain, typ):
        """
        if it exists, delete an A or AAAA record
        (because the corresponding IP is not available)
        """
        self.log(f"checking record {typ} for {subdomain}.{domain}")
        result = self.client.get(
            f"/domain/zone/{domain}/record", fieldType=typ, subDomain=subdomain
        )
        if len(result) == 1:
            # record exists, delete it
            record_id = result[0]
            self.log(f"### deleting record {typ} for {subdomain}.{domain}")
            self.client.delete(f"/domain/zone/{domain}/record/{record_id}")
            self.client.post(f"/domain/zone/{domain}/refresh")
            self.record_changed += 1

    def update_record_if_needed(self):
        current_ipv4 = self.get_current_ip(4)
        current_ipv6 = self.get_current_ip(6)
        self.log(f"current ips: {current_ipv4} ; {current_ipv6}")

        # reload saved values & compare
        try:
            with open(self.current_ip_file) as _file:
                old_time, old_ipv4, old_ipv6 = yaml.safe_load(_file)
            need_update = (old_ipv4 != current_ipv4) or (
                old_ipv6 != current_ipv6
            )
        except OSError:
            self.log("No old ips recorded")
            need_update = True
        if not need_update:
            self.log("nothing to do!")
            return

        self.record_changed = 0
        try:
            for _host, values in self.settings["hosts"].items():
                domain = values["domain"]
                for subdomain in values["subdomains"]:
                    self.log("#" * 70)
                    self.log(f"Updating '{subdomain}' subdomain")
                    if ("ipv4" in values) and (values["ipv4"] is not False):
                        if current_ipv4:
                            ttl = (
                                self.settings["default_ttl"]
                                if ("ttl" not in values)
                                else values["ttl"]
                            )
                            self.update_record(
                                domain, subdomain, current_ipv4, _ttl=ttl
                            )
                        else:
                            self.delete_record(domain, subdomain, "A")
                    else:
                        self.log(
                            f"Not touching A record for {subdomain}.{domain}, as instructed"
                        )
                    if ("ipv6" in values) and (values["ipv6"] is not False):
                        if current_ipv6:
                            ttl = (
                                self.settings["default_ttl"]
                                if ("ttl" not in values)
                                else values["ttl"]
                            )
                            self.update_record(
                                domain, subdomain, current_ipv6, _ttl=ttl
                            )
                        else:
                            self.delete_record(domain, subdomain, "AAAA")
                    else:
                        self.log(
                            f"Not touching AAAA record for {subdomain}.{domain}, as instructed"
                        )
            # all self.settings["hosts"] records have been updated without errors, log change and save current addresses
            self.log(
                f"new addresses {current_ipv4} ; {current_ipv6} -- {self.record_changed} records updates"
            )
            with open(self.current_ip_file, "w") as _file:
                yaml.dump([time.time(), current_ipv4, current_ipv6], _file)
        # some error occurred (API down, keys expired...?),
        except Exception as e:
            msg = f"Error while updating records: {str(e)} ; Records updated with new addresses: {self.record_changed} ipv4: {current_ipv4} ipv6: {current_ipv6}"
            self.log(msg)
            # not saving new addresses, so that update is attempted again.


if __name__ == "__main__":
    update = OVHIpUpdate()
    update.run()
