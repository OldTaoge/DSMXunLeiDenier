# run as daemon
# Author: Oldtaoge
# all rights reserved

# 用于 DSM Download Station 的工具，用于拒绝迅雷（仅下载）
import os
import time
from urllib import request
import json

# 如果脚本直接运行而非被导入，则执行以下代码块
if __name__ == '__main__':
    # 初始化变量
    sid = ""
    peer_raw = []
    xun_list = []
    denied_addr = set()
    deny_addr = set()

    # 打开名为 "data.json" 的文件并加载其中的 JSON 数据
    with open(os.path.dirname(__file__) + "/data.json", "r") as df:
        dataDB = json.load(df)

    # 如果 dataDB 为空，抛出异常
    if dataDB is None:
        raise Exception("打开 data.json 出错")

    # 从 dataDB 中提取配置信息
    USERNAME = dataDB["data"]["config"]["USERNAME"]
    PASSWORD = dataDB["data"]["config"]["PASSWORD"]
    SYNOAPI_PREFIX = dataDB["data"]["config"]["SYNOAPI_PREFIX"]
    LOGIN_API = dataDB["data"]["config"]["LOGIN_API"]
    PEER_API = dataDB["data"]["config"]["PEER_API"]
    EMULE_API = dataDB["data"]["config"]["EMULE_API"]
    # 将 LOGIN_API 中的 "USERNAME" 和 "PASSWORD" 替换为实际的用户名和密码
    LOGIN_API = LOGIN_API.replace("USERNAME", USERNAME).replace("PASSWORD", PASSWORD)
    BLACKLIST = dataDB["data"]["blacklist"]
    EMULE_BLACKLIST = dataDB["data"]["emule_blacklist"]
    PEERDB = dataDB["data"]["peerDB"]

    # 无限循环
    while True:
        try:
            # 尝试获取 sid（会话 ID）以进行身份验证
            data = json.loads(request.urlopen(SYNOAPI_PREFIX + LOGIN_API).read().decode('utf-8'))
            if data.get("error") is None:
                sid = data["data"]["sid"]
            else:
                # 如果出错，抛出异常
                raise Exception(data.get("error"))
            
            # 无限循环，处理 peer（下载代理）信息
            while True:
                # 获取任务列表的 peer 信息
                data = json.loads(request.urlopen(SYNOAPI_PREFIX + PEER_API + "&_sid=" + sid).read().decode('utf-8'))
                for task in data["data"]["tasks"]:
                    if task.get("additional") is not None:
                        # 将 peer 信息添加到 peer_raw 列表中
                        peer_raw.extend(task["additional"]["peer"])
                for peer in peer_raw:
                    for blpn in BLACKLIST:
                        # 如果 peer 的代理名称包含在黑名单中，则将其地址加入到 deny_addr 集合中
                        if blpn in peer["agent"]:
                            deny_addr.add(peer["address"])
                            break
                        if str(PEERDB.get(blpn)) in peer["agent"]:
                            deny_addr.add(peer["address"])
                            break

                # 获取 emule 任务的信息，但代码中只有一个占位符注释
                data = json.loads(request.urlopen(SYNOAPI_PREFIX + EMULE_API + "&_sid=" + sid).read().decode('utf-8'))
                for task in data["data"]["task"]:
                    for blpn in EMULE_BLACKLIST:
                        if blpn in task.get("client_name"):
                            pass 
                            # TODO
                
                # 清空 peer_raw 列表
                peer_raw.clear()

                # 处理新增加的拒绝地址
                for new_deny in deny_addr - denied_addr:
                    if ":" in new_deny:
                        # 使用 iptables 命令添加 IPv6 地址的阻止规则
                        os.system("ip6tables -I OUTPUT -d %s -j DROP" % new_deny)
                        os.system("ip6tables -I OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % new_deny)
                    else:
                        # 使用 iptables 命令添加 IPv4 地址的阻止规则
                        os.system("iptables -I OUTPUT -d %s -j DROP" % new_deny)
                        os.system("iptables -I OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % new_deny)
                
                # 处理不再需要阻止的地址
                for old_deny in denied_addr - deny_addr:
                    if ":" in old_deny:
                        os.system("ip6tables -D OUTPUT -d %s -j DROP" % old_deny)
                        os.system("ip6tables -D OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % old_deny)
                    else:
                        os.system("iptables -D OUTPUT -d %s -j DROP" % old_deny)
                        os.system("iptables -D OUTPUT -m limit -d %s --limit 1/s --limit-burst 1 -j ACCEPT" % old_deny)
                
                # 更新 denied_addr 集合，并清空 deny_addr 集合
                denied_addr = deny_addr.copy()
                deny_addr.clear()
                
                # 等待 5 秒钟
                time.sleep(5)
        except Exception as e:
            # 捕获并打印异常
            print(e)
