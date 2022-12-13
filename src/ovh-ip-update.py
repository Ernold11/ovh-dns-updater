#!/usr/bin/env python

import os
import ovh
import sys
import yaml
import requests
import time
import logging
from logging.handlers import TimedRotatingFileHandler


class OVHIpUpdate:
    def __init__(self) -> None:
        self.current_ip_file = "/tmp/current_ip.yaml"
        self.record_changed = 0
        self.settings = self.load_config()
        self.logger = self.get_logger("/tmp/ovh-dns-updater.log")
        self.supervisord_logger = self.get_logger("/dev/fd/1")
        self.client = ovh.Client(**self.settings["ovh"])

    def get_logger(self, path):
        logger = logging.getLogger("MAIN")
        logger.setLevel(logging.INFO)
        
        handler = TimedRotatingFileHandler(path,
                                       when="d",
                                       interval=1,
                                       backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        logger.addHandler(handler)
        
        return logger


    def load_config(self):
        conf_file_path = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "config", "conf.yaml")

        with open(conf_file_path, "r") as _file:
            return yaml.load(_file, Loader=yaml.FullLoader)

    def run(self):
        sleep_time = int(os.getenv('SLEEP_TIME'))
        while True:
            self.update_record_if_needed()
            self.log("Sleep {}s".format(sleep_time))
            time.sleep(sleep_time)

    def get_current_ip(self, v=4):
        if v == 4:
            url_list = ["https://api.ipify.org",
                        "https://ipv4.lafibre.info/ip.php", "https://v4.ident.me"]
        else:
            url_list = ["https://api6.ipify.org",
                        "https://ipv6.lafibre.info/ip.php", "https://v6.ident.me"]
        ip = ""
        message = ""
        for url in url_list:
            try:
                r = requests.get(url, timeout=30.0)
            except requests.exceptions.RequestException as e:
                message += "failed getting ipv{} address from {} because {} occurred\n".format(
                    v, url, str(e))
                continue
            if r.status_code == requests.codes.ok:
                ip = r.text
                break
            else:
                message += "Cannot get IPv{} from {}: requests.get returned status_code {}.\n".format(
                    v, url, r.status_code)
        if ip != "":
            return ip
        elif v in self.settings["ip_versions_required"]:
            message += "Failed getting required IPv{}. There is most likely a real connectivity problem. Aborting". format(
                v)
            self.log(message)
            quit()
        else:
            return False

    def log(self, msg):
        self.logger.info(msg)
        self.supervisord_logger.info(msg)

    def update_record(self, domain, subdomain, new_ip, _ttl=600):
        # Update the (A or AAAA) record with the provided IP

        typ = 'AAAA' if ":" in new_ip else 'A'
        self.log("checking record {} for {}.{}".format(typ, subdomain, domain))
        path = "/domain/zone/{}/record".format(domain)
        result = self.client.get(path,
                                 fieldType=typ,
                                 subDomain=subdomain
                                 )

        if len(result) != 1:
            # creating NEW record
            result = self.client.post(path,
                                      fieldType=typ,
                                      subDomain=subdomain,
                                      target=new_ip,
                                      ttl=_ttl
                                      )
            self.client.post('/domain/zone/{}/refresh'.format(domain))
            result = self.client.get(path,
                                     fieldType=typ,
                                     subDomain=subdomain
                                     )
            record_id = result[0]
            self.record_changed += 1
            self.log("### created new record {} for {}.{}".format(
                typ, subdomain, domain))
        else:
            # record exists
            record_id = result[0]
            path = "/domain/zone/{}/record/{}".format(domain, record_id)
            result = self.client.get(path)
            oldip = result['target']
            self.log('record exists, with ip: {}'.format(oldip))
            if oldip == new_ip:
                self.log('nothing to do')
                return
            else:
                self.log('updating to: {}'.format(new_ip))
                result = self.client.put(path,
                                         subDomain=subdomain,
                                         target=new_ip,
                                         ttl=_ttl
                                         )
                self.client.post('/domain/zone/{}/refresh'.format(domain))
                self.record_changed += 1
        # checking changes
        result = self.client.get(
            "/domain/zone/{}/record/{}".format(domain, record_id))
        if new_ip != result['target']:
            self.record_changed -= 1
            raise Exception("Error updating {}.{} with {}".format(
                subdomain, domain, new_ip))

    def delete_record(self, domain, subdomain, typ):
        """
        if it exists, delete an A or AAAA record
        (because the corresponding IP is not available)
        """
        self.log("checking record {} for {}.{}".format(typ, subdomain, domain))
        result = self.client.get("/domain/zone/{}/record".format(domain),
                                 fieldType=typ,
                                 subDomain=subdomain
                                 )
        if len(result) == 1:
            # record exists, delete it
            record_id = result[0]
            self.log("### deleting record {} for {}.{}".format(
                typ, subdomain, domain))
            self.client.delete(
                "/domain/zone/{}/record/{}".format(domain, record_id))
            self.client.post('/domain/zone/{}/refresh'.format(domain))
            self.record_changed += 1

    def update_record_if_needed(self):
        current_ipv4 = self.get_current_ip(4)
        current_ipv6 = self.get_current_ip(6)
        self.log('current ips: {} ; {}'.format(current_ipv4, current_ipv6))

        # reload saved values & compare
        try:
            with open(self.current_ip_file, 'r') as _file:
                old_time, old_ipv4, old_ipv6 = yaml.load(
                    _file, Loader=yaml.FullLoader)
            need_update = (old_ipv4 != current_ipv4) or (old_ipv6 != current_ipv6)
        except IOError:
            self.log("No old ips recorded")
            need_update = True
        if need_update:
            self.record_changed = 0
            try:
                for host, values in self.settings["hosts"].items():
                    domain = values["domain"]
                    for subdomain in values["subdomains"]:
                        self.log("Updating {} subdomain".format(subdomain))
                        if ('ipv4' in values) and (values['ipv4'] != False):
                            if current_ipv4:
                                ttl = self.settings["default_ttl"] if (
                                    'ttl' not in values) else values['ttl']
                                self.update_record(
                                    domain, subdomain, current_ipv4, _ttl=ttl)
                            else:
                                self.delete_record(domain, subdomain, 'A')
                        else:
                            self.log("Not touching A record for {}.{}, as instructed".format(
                                subdomain, domain))
                            pass
                        if ('ipv6' in values) and (values['ipv6'] != False):
                            if current_ipv6:
                                ttl = self.settings["default_ttl"] if (
                                    'ttl' not in values) else values['ttl']
                                self.update_record(
                                    domain, subdomain, current_ipv6, _ttl=ttl)
                            else:
                                self.delete_record(domain, subdomain, 'AAAA')
                        else:
                            self.log("Not touching AAAA record for {}.{}, as instructed".format(
                                subdomain, domain))
                            pass
                # all self.settings["hosts"] records have been updated without errors, log change and save current addresses
                self.log("new addresses {} ; {} -- {} records updates".format(
                    current_ipv4, current_ipv6, self.record_changed))
                with open(self.current_ip_file, 'w') as _file:
                    yaml.dump([time.time(), current_ipv4, current_ipv6], _file)
            # some error occured (API down, keys expired...?),
            except Exception as e:
                msg = "Error while updating records: {} ; Records updated with new addresses: {} ipv4: {} ipv6: {}".format(
                    str(e), self.record_changed, current_ipv4, current_ipv6)
                self.log(msg)
                # not saving new addresses, so that update is attempted again.
        else:
            self.log("nothing to do!")
            pass


if __name__ == "__main__":
    update = OVHIpUpdate()
    update.run()
