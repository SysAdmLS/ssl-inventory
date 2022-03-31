import json
import socket
import logging
from timeit import default_timer as timer

from cryptography import x509
from elasticsearch import Elasticsearch
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
import threading
import queue

# config
es = Elasticsearch([{'host': 'localhost', 'port': 9200, 'scheme': 'http'}])  # elasticsearch connection


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
        es.index(index=self.es_index, id=entry['ip'] + ':' + str(entry['port']), document=entry)

    def parse(self):
        """Parse the masscan json"""
        for result in self.data:
            for port in result['ports']:

                try:
                    if port['service']['name'] == 'X509':
                        certificate = Cert(
                            '-----BEGIN CERTIFICATE-----\n' + port['service']['banner'] + '\n-----END CERTIFICATE-----')
                        print(result)

                        dataentry = {
                            'timestamp': result['timestamp'],
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
                            logging.warning(e)

                        print(dataentry)
                        self.__index(dataentry)
                except KeyError:
                    pass
                except ValueError:
                    logging.warning(result['ip'] + ' failed')


class ScanresultNmap():
    def __init__(self, indexname: str):
        self.es_index = indexname

    def __index(self, entry):
        """Function to write the datapoint to elasticsearch"""
        es.index(index=self.es_index, id=entry['ip'] + ':' + str(entry['port']), document=entry)

    def parsefromfile(self, xmlfile: str):
        """Function to parse nmap xmlfile output to elasticsearch"""
        nmap_report = NmapParser.parse_fromfile(xmlfile)
        self.parse(nmap_report)

    def parse(self, nmap_report):
        for host in nmap_report.hosts:
            for service in host.services:
                if service.scripts_results:
                    for result in service.scripts_results:
                        certificate = Cert(result['elements']['pem'])

                        dataentry = {
                            'timestamp': host.starttime,
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

                        print(dataentry)
                        self.__index(dataentry)

    def masscantonmap(self, masscan_json: str):
        with open(masscan_json) as f:
            data = json.load(f)
        for result in data:
            for port in result['ports']:
                print(f"{result['ip']} : {port['port']}")
                nm = NmapProcess(result['ip'], options=f"-p{port['port']} --script ssl-cert --script-timeout 2")
                nm.run()
                self.parse(NmapParser.parse(nm.stdout))

    def masscantonmap_threaded(self,masscan_json: str, n_threads: int):
        q = queue.Queue()
        with open(masscan_json) as f:
            data = json.load(f)
        scanlist = {}
        for result in data:
            for port in result['ports']:
                print(f"{result['ip']} : {port['port']}")
                try:
                    scanlist[result['ip']].add(str(port['port']))
                except KeyError:
                    scanlist[result['ip']] = {str(port['port'])}
        for x in scanlist:
            q.put([x,','.join(scanlist[x])])
        for _ in range(n_threads):
            threading.Thread(target=self.__masscantonmap_worker,
                             args=(q,)).start()
        q.join()
    def __masscantonmap_worker(self, q):
        while True:
            try:
                work = q.get(timeout=1)
            except queue.Empty:
                return
            print(work)
            nm = NmapProcess(work[0], options=f"-p{work[1]} --script ssl-cert --script-timeout 10")
            nm.run()
            self.parse(NmapParser.parse(nm.stdout))
            q.task_done()

if __name__ == '__main__':
    # ScanresultMasscan('test.json', 'test')
    # ScanresultMasscan('test2.json', 'test')
    # ScanresultNmap('test').parsefromfile('test.xml')
    start = timer()
    #ScanresultNmap('test_singlenmap').masscantonmap('test.json')
    ScanresultNmap('test').masscantonmap_threaded('test.json', 10)

    end = timer() - start
    print(f"{end} seconds elapsed")
