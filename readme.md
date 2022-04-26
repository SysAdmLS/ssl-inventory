# SSL Certificate Inventory (POC)

This is a proof of concept on how to inventorize used SSL Certificates for example in an enterprise environment. The idea was to
use  [masscan](https://github.com/robertdavidgraham/masscan) as the primary network scanner utilizing its huge speed advantage over Nmap and importing the results into an Elasticsearch-Kibana Stack for exploring and generating alerts.  

However, there are some **limitations** to that: 
1. Masscan has limited support for [grabbing](https://github.com/robertdavidgraham/masscan#banner-checking) the SSL Certificate from services other than HTTPS/SMTP/IMAP.
2. Masscan uses a **hardcoded** TLS 1.1 "Client Hello" packet (see [here](https://github.com/robertdavidgraham/masscan/blob/144c527ed55275ee9fbb80bb14fbb5e3fcff3b7e/src/proto-ssl.c#L1059)). This leads to problems retrieving the SSL Certificate from servers not supporting TLS 1.1, which is deprecated [since March 2021](https://datatracker.ietf.org/doc/rfc8996/).
3. Masscan might not be available on the users' system.

To combat these limitations I implemented several ways for importing and generating scan results.

I also compiled my own masscan binary, replacing the TLS 1.1 packet with TLS 1.2, as this increased coverage and reduced connection errors significantly when grabbing for Certificates. The binary is included in this repo. Compiling your own TLS 1.2 masscan version is as easy as capturing a TLS 1.2 handshake (e.g. ``curl --tlsv1.2 https://10.X.X.X``   ) with wireshark and inserting the packet [here](https://github.com/robertdavidgraham/masscan/blob/144c527ed55275ee9fbb80bb14fbb5e3fcff3b7e/src/proto-ssl.c#L1059).
# Configuration

# Usage

# Alerting

# Performance
To measure performance and show how threading and code optimization can improve runtime I tested several version of this project while developing it.

My first version parsed the masscan results line by line and rescanned every result with a single nmap instance. After that I implemented multi threading because nmap does not support that natively. In the last and final version nmap is fed a precomputed list instead of single lines from the masscan results (masscan outputs one host/port combination per line). 

This cut down the time needed significantly from 1327 seconds to only 42 seconds as seen in the following chart.
<img height="100%" src="images/processtime.png" title="Performance comparison for parsing and scanning a masscan file" width="100%"/>

Comparing the method of using masscan to prescan the network and then using nmap to do the certificate extraction vs solely using nmap yielded some interesting results. Not only was it way faster but also increased the detection rate of hosts, services and certificates. It seems that nmap has problems scanning large subnets in combination with the ssl-script. This result could be replicated over several runs though I did not investigate the cause of this.

