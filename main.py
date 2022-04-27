import json
import socket
import logging
import threading
import queue

from timeit import default_timer as timer
from tqdm import tqdm
from cryptography import x509
from elasticsearch import Elasticsearch
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from opensearchpy import OpenSearch
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # disable urllib3 warning coming from the elastic/open-search library bc of self signed tls

# config
#es = Elasticsearch([{'host': 'localhost', 'port': 9200, 'scheme': 'http'}])  # elasticsearch connection
es = OpenSearch([{'host': 'localhost', 'port': 9200}],http_auth=('admin', 'admin'),use_ssl = True,verify_certs = False) # opensearch connection

# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

class Cert:
    """Class to handle the certificate"""

    def __init__(self, pem: str):
        self.certobj = x509.load_pem_x509_certificate(str.encode(pem))
        self.notvalidafter = None
        self.issuer = None
        self.cn = None
        self.san = None

        self.__parse()

    def __parse(self):
        """Parses the cert fields/data"""
        self.notvalidafter = self.certobj.not_valid_after

        # catches certs not having a valid subject
        if self.certobj.subject.get_attributes_for_oid(x509.OID_COMMON_NAME):
            self.cn = self.certobj.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[
                0].value.strip()

        # catches certs not having a valid issuer
        if self.certobj.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME):
            self.issuer = self.certobj.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)[
                0].value.strip()
        # catches certs not having SAN's
        try:
            self.san = self.certobj.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except:
            self.san = ''


class ScanresultMasscan:
    """Class for importing Masscan results in json format to elasticsearch"""

    def __init__(self, jsonfile: str, indexname: str):
        self.jsonfile = jsonfile
        with open(self.jsonfile) as f:
            self.data = json.load(f)

        self.es_index = indexname
        self.__parse()

    def __index(self, entry):
        """Function to write the datapoint to elasticsearch"""
        #es.index(index=self.es_index, id=entry['ip'] + ':' + str(entry['port']), document=entry) # elasticsearch index function
        es.index(index=self.es_index, id=entry['ip'] + ':' + str(entry['port']), body=entry, refresh=True) # opensearch index function
    def __parse(self):
        """Parse the masscan json"""
        for result in self.data:
            for port in result['ports']:

                try:
                    if port['service']['name'] == 'X509':
                        certificate = Cert(
                            '-----BEGIN CERTIFICATE-----\n' + port['service']['banner'] + '\n-----END CERTIFICATE-----')
                        logger.debug(result)

                        dataentry = {
                            'timestamp': datetime.fromtimestamp(int(result['timestamp'])),
                            'ip': result['ip'],
                            'hostname': '',
                            'port': int(port['port']),
                            'notvalidafter': certificate.notvalidafter,
                            'subject': certificate.cn,
                            'issuer': certificate.issuer,
                            'SANs': certificate.san

                        }

                        try:
                            dataentry['hostname'] = socket.gethostbyaddr(result['ip'])[0]
                        except socket.herror as e:
                            logger.warning(e)

                        logger.debug(dataentry)
                        self.__index(dataentry)
                except KeyError:
                    pass
                except ValueError:
                    logger.warning(result['ip'] + ' failed')


class ScanresultNmap():
    """Class for generating and importing nmap results in json format to elasticsearch"""
    def __init__(self, indexname: str):
        self.es_index = indexname

    def __index(self, entry):
        """Function to write the datapoint to elasticsearch"""
        #es.index(index=self.es_index, id=entry['ip'] + ':' + str(entry['port']), document=entry) # elasticsearch index function
        es.index(index=self.es_index, id=entry['ip'] + ':' + str(entry['port']), body=entry,refresh = True) # opensearch index function
    def parsefromfile(self, xmlfile: str):
        """Function to parse nmap xmlfile output to elasticsearch"""
        nmap_report = NmapParser.parse_fromfile(xmlfile)
        self.parse(nmap_report)

    def parse(self, nmap_report):
        """Function to parse nmap output to elasticsearch"""
        for host in nmap_report.hosts:
            for service in host.services:
                if service.scripts_results:
                    for result in service.scripts_results:
                        certificate = Cert(result['elements']['pem'])

                        dataentry = {
                            'timestamp': datetime.fromtimestamp(int(host.starttime)),
                            'ip': host.ipv4,
                            'hostname': '',
                            'port': int(service.port),
                            'notvalidafter': certificate.notvalidafter,
                            'subject': certificate.cn,
                            'issuer': certificate.issuer,
                            'SANs': certificate.san

                        }
                        if host.hostnames:
                            dataentry['hostname'] = host.hostnames[0]

                        logger.debug(dataentry)
                        self.__index(dataentry)

    def masscantonmap(self, masscan_json: str):
        """Deprecated, masscantonmap_threaded!! Function to parse masscan results and rescan for certificates with nmap"""
        with open(masscan_json) as f:
            data = json.load(f)
        for result in data:
            for port in result['ports']:
                logger.debug(f"{result['ip']} : {port['port']}")
                nm = NmapProcess(result['ip'], options=f"-p{port['port']} --script ssl-cert --script-timeout 2")
                nm.run()
                self.parse(NmapParser.parse(nm.stdout))

    def masscantonmap_threaded(self,masscan_json: str, n_threads: int):
        """Function to parse masscan results and rescan for certificates with nmap but with multi threading and optimized target list building"""
        q = queue.Queue()
        with open(masscan_json) as f:
            data = json.load(f)
        scanlist = {}
        for result in data:
            for port in result['ports']:
                logger.debug((f"{result['ip']} : {port['port']}"))
                # building a dictionary that holds the unique ports for every specific ip found by masscan using a set for the ports
                try:
                    scanlist[result['ip']].add(str(port['port']))
                except KeyError:
                    scanlist[result['ip']] = {str(port['port'])}
        for x in scanlist:
            q.put([x,','.join(scanlist[x])])
        pbar = tqdm(desc='Scanning hosts for certificates',total=q.qsize())
        for _ in range(n_threads):
            threading.Thread(target=self.__masscantonmap_worker,
                             args=(q,pbar)).start()
        q.join()
        pbar.close()
    def __masscantonmap_worker(self, q,pbar :tqdm):
        while True:
            try:
                work = q.get(timeout=1)
            except queue.Empty:
                return
            logger.debug(work)
            nm = NmapProcess(work[0], options=f"-p{work[1]} --script ssl-cert --script-timeout 10")
            nm.run()
            self.parse(NmapParser.parse(nm.stdout))
            pbar.update()
            q.task_done()

if __name__ == '__main__':
    start = timer()
    ScanresultNmap('test').masscantonmap_threaded('test.json', 10)
    end = timer() - start
    print(f"{end} seconds elapsed")
