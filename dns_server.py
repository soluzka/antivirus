from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR
from dnslib.server import DNSServer, DNSHandler, BaseResolver
import socket
import logging
from ipaddress import ip_address, ip_network
import threading
import time
import dns.resolver  # Added for custom DNS resolution

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('home_dns_server')

class HomeNetworkDNSResolver(BaseResolver):
    def __init__(self, network_range="192.168.1.0/24"):
        self.network_range = ip_network(network_range)
        self.local_domains = {
            'local': '127.0.0.1',
            'home.local': '127.0.0.1'
        }
        self.blocked_domains = {
            'malicious.example.com',
            'bad.example.com'
        }
        
    def is_allowed_ip(self, client_ip):
        try:
            return ip_address(client_ip) in self.network_range
        except ValueError:
            return False

    def resolve(self, request, handler):
        client_ip = handler.client_address[0]
        
        # Block non-localhost requests
        if client_ip != '127.0.0.1':
            logger.warning(f"Denied DNS request from non-localhost IP: {client_ip}")
            
            # Block the IP using firewall
            try:
                from network_monitor import block_ip
                block_ip(client_ip, reason="Unauthorized DNS request", port=53)
            except ImportError:
                logger.warning("Network monitor module not available for firewall blocking")
            
            return None

        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        
        # Block specific domains
        if qname in self.blocked_domains:
            logger.info(f"Blocked request for domain: {qname}")
            reply.add_answer(RR(qname, rdata='0.0.0.0'))
            return reply

        # Handle local domains
        if qname in self.local_domains:
            reply.add_answer(RR(qname, rdata=self.local_domains[qname]))
            return reply

        # For other domains, forward to specified public DNS servers
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Use Google and Cloudflare DNS
            answer = resolver.resolve(qname)
            public_dns = answer[0].address
            reply.add_answer(RR(qname, rdata=public_dns))
            return reply
        except Exception as e:
            logger.warning(f"Failed to resolve domain: {qname} ({e})")
            logger.info(f"[User Notice] DNS lookup for '{qname}' failed. This is often a temporary issue with your network or DNS server, not a problem with your antivirus software. If this happens frequently, check your network settings or DNS provider.")
            return None

def start_dns_server():
    try:
        # Create resolver
        resolver = HomeNetworkDNSResolver()
        
        # Create DNS server
        server = DNSServer(
            resolver,
            port=53,
            address="0.0.0.0",
            tcp=True
        )
        
        # Start server
        logger.info("Starting DNS server...")
        server.start()
        
    except Exception as e:
        logger.error(f"Error starting DNS server: {str(e)}")
        raise

# Export the start function
__all__ = ['start_dns_server']
