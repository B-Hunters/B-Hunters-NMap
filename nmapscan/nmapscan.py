from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import re
import nmap
from bson.objectid import ObjectId

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
            # The platform names the target as host:port.  nmap does not
            # understand that notation - it would take the whole string
            # for a host name - and it would then scan the default ports
            # and miss the port the application actually listens on.
            host, separator, port = newurl.partition(":")
            if not (separator and port.isdigit()):
                host = newurl
            else:
                options = f"{options} -p {port}"
            scanner = nmap.PortScanner()
            # Run a basic scan on the target
            scanner.scan(host, arguments=options)
            # Print the scan results
            for host in scanner.all_hosts():
                data={}
                data["target"]=newurl
                # A host that is up but has no open port is a result, not
                # an error: the port list has to exist before the protocol
                # loop, because the loop may not run at all.
                data["ports"]=[]
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
        report_id=task.payload_persistent["report_id"]
        self.log.info("Starting processing new url")
        self.log.warning(url)
        self.update_task_status(url,"Started")

        result,techs=self.scan(url)
        self.waitformongo()

        db=self.db

        self.log.info(result)
        collection = db["reports"]
        existing_document = collection.find_one({"_id":ObjectId(report_id)})
        if existing_document is not None:
            if result:
                collection.update_one({"_id":ObjectId(report_id)}, {'$push': {'Ports': result}}, upsert=True)
            ports = []
            for item in result:
                ports.extend(item["ports"])
            if ports != []:
                new_ports=[]
                for port in ports:
                    if "Port: 80 " not in port and "Port: 443 " not in port:
                        new_ports.append(port)
                if new_ports != []:
                            
                    ports_str = "\n".join(new_ports)       
                    self.send_discord_webhook("Nmap Result "+url,ports_str,"main")
        if techs != {}:
            if existing_document:
                if "Technology" in existing_document and "nmap" in existing_document["Technology"]:
                    collection.update_one({"_id":ObjectId(report_id)}, {"$push": {"Technology.nmap": techs}})
                else:
                    collection.update_one({"_id":ObjectId(report_id)}, {"$set": {"Technology.nmap": [techs]}})

        self.update_task_status(url,"Finished")
