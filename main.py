# run as daemon
# Author: Oldtaoge
# all rights reserved

# tool for DSM Download Station to deny XunLei(Only download
import os
import time
from urllib import request
import json


if __name__ == '__main__':
    sid = ""
    peer_raw = []
    xun_list = []
    denied_addr = set()
    deny_addr = set()
    with open(os.path.dirname(__file__) + "/data.json", "r") as df:
        dataDB = json.load(df)
    if dataDB is None:
        raise Exception("OPEN data.json ERROR")
    USERNAME = dataDB["data"]["config"]["USERNAME"]
    PASSWORD = dataDB["data"]["config"]["PASSWORD"]
    SYNOAPI_PREFIX = dataDB["data"]["config"]["SYNOAPI_PREFIX"]
    LOGIN_API = dataDB["data"]["config"]["LOGIN_API"]
    PEER_API = dataDB["data"]["config"]["PEER_API"]
    EMULE_API = dataDB["data"]["config"]["EMULE_API"]
    LOGIN_API = LOGIN_API.replace("USERNAME", USERNAME).replace("PASSWORD", PASSWORD)
    BLACKLIST = dataDB["data"]["blacklist"]
    EMULE_BLACKLIST = dataDB["data"]["emule_blacklist"]
    PEERDB = dataDB["data"]["peerDB"]
    while True:
        try:
            data = json.loads(request.urlopen(SYNOAPI_PREFIX + LOGIN_API).read().decode('utf-8'))
            if data.get("error") is None:
                sid = data["data"]["sid"]
            else:
                raise Exception(data.get("error"))
            while True:
                data = json.loads(request.urlopen(SYNOAPI_PREFIX + PEER_API + "&_sid=" + sid).read().decode('utf-8'))
                for task in data["data"]["tasks"]:
                    if task.get("additional") is not None:
                        peer_raw.extend(task["additional"]["peer"])
                for peer in peer_raw:
                    for blpn in BLACKLIST:
                        if blpn in peer["agent"]:
                            deny_addr.add(peer["address"])
                            break
                        if str(PEERDB.get(blpn)) in peer["agent"]:
                            deny_addr.add(peer["address"])
                            break

                data = json.loads(request.urlopen(SYNOAPI_PREFIX + EMULE_API + "&_sid=" + sid).read().decode('utf-8'))
                for task in data["data"]["task"]:
                    for blpn in EMULE_BLACKLIST:
                        if blpn in task.get("client_name"):
                            pass 
                            # TODO
                peer_raw.clear()
                for new_deny in deny_addr - denied_addr:
                    if ":" in new_deny:
                        os.system("ip6tables -I OUTPUT -d %s -j DROP" % new_deny)
                        os.system("ip6tables -I OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % new_deny)
                    else:
                        os.system("iptables -I OUTPUT -d %s -j DROP" % new_deny)
                        os.system("iptables -I OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % new_deny)
                for old_deny in denied_addr - deny_addr:
                    if ":" in old_deny:
                        os.system("ip6tables -D OUTPUT -d %s -j DROP" % old_deny)
                        os.system("ip6tables -D OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % old_deny)
                    else:
                        os.system("iptables -D OUTPUT -d %s -j DROP" % old_deny)
                        os.system("iptables -D OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % old_deny)
                denied_addr = deny_addr.copy()
                deny_addr.clear()
                time.sleep(5)
        except Exception as e:
            print(e)
