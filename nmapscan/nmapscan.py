from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import re
import nmap

class nmapscan(BHunters):
    """
    B-Hunters Nmap developed by 0xBormaa
    """

    identity = "B-Hunters-Nmap"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "subdomain", "stage": "new"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
                    
    def scan(self,url):        
        result,techs=self.nmapcommand(url)
        if result !=[]:
            return result,techs
        return [],{}
    def nmapcommand(self,newurl):
        result=[]
        techs={}
        try:
            options = "-sC -sV"
            scanner = nmap.PortScanner()
            # Run a basic scan on the target
            scanner.scan(newurl, arguments=options)
            # Print the scan results
            for host in scanner.all_hosts():
                data={}
                data["target"]=newurl
                # print("Host: ", host)
                data["host"]=host
                # print("State: ", scanner[host].state())
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    # print(scanner[host][proto])
                    data["ports"]=[]
                    for port in ports:
                        script = ""
                        port_info = scanner[host][proto][port]
                        if port_info.get('state') == "open":
                            script = port_info.get('script', "")
                            port_str = str(port)
                            state = port_info.get('state', '')
                            product = port_info.get('product', '')
                            version = port_info.get('version', '')
                            
                            portdata = f"Port: {port_str} ,State: {state} ,Product: {product} {version}"
                            if script:
                                portdata += f" ,Script: {script}"
                            data["ports"].append(portdata)
                            if product !="":
                                techs[newurl]=[product,version]
                firewall=False
                for portdata in data["ports"]:
                    if "cloudflare" in portdata.lower() or "cloudfront" in portdata.lower():
                        firewall=True
                self.log.info(data)
                if firewall ==False:
                    
                    result.append(data)
        except Exception as e:
            self.log.error(e)
            self.update_task_status(newurl,"Failed")

            raise Exception(e)
        
        return result,techs
        
    def process(self, task: Task) -> None:
        
        url = task.payload["subdomain"]
        url = re.sub(r'^https?://', '', url)
        url = url.rstrip('/')
        self.log.info("Starting processing new url")
        self.log.warning(url)
        self.update_task_status(url,"Started")

        result,techs=self.scan(url)
        db=self.db

        self.log.info(result)
        collection = db["domains"]
        existing_document = collection.find_one({"Domain": url})
        if existing_document is not None:
            collection.update_one({"Domain": url}, {'$push': {'Ports': result}})
            ports = []
            for item in result:
                ports.extend(item["ports"])

            ports_str = "\n".join(ports)
            self.send_discord_webhook("Nmap Result "+url,ports_str,"main")
        if techs != {}:
            domain_document = collection.find_one({"Domain": url})
            if domain_document:
                if "Technology" in domain_document and "nmap" in domain_document["Technology"]:
                    collection.update_one({"Domain": url}, {"$push": {"Technology.nmap": techs}})
                else:
                    collection.update_one({"Domain": url}, {"$set": {"Technology.nmap": [techs]}})

        self.update_task_status(url,"Finished")
