#!/usr/bin/env python3
"""
Validators module

Provides functions for validating domain names, IP addresses, and ports.
"""

import re
import socket

def is_valid_domain(domain):
    """
    Check if a domain name is valid.
    
    Args:
        domain (str): Domain name to check.
    
    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    if not domain:
        return False
    
    # Skip IP addresses
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
        return False
    
    # Simple regex to validate domain format
    domain_pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(domain_pattern.match(domain))

def is_valid_ip(ip):
    """
    Check if an IP address is valid.
    
    Args:
        ip (str): IP address to check.
    
    Returns:
        bool: True if the IP address is valid, False otherwise.
    """
    if not ip:
        return False
    
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_port(port):
    """
    Check if a port number is valid.
    
    Args:
        port (int): Port number to check.
    
    Returns:
        bool: True if the port is valid, False otherwise.
    """
    try:
        port = int(port)
        return 0 < port < 65536
    except (ValueError, TypeError):
        return False

def is_valid_url(url):
    """
    Check if a URL is valid.
    
    Args:
        url (str): URL to check.
    
    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    if not url:
        return False
    
    # Simple regex to validate URL format
    url_pattern = re.compile(
        r'^(https?:\/\/)?'  # http:// or https://
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'  # domain
        r'(\:[0-9]{1,5})?'  # port
        r'(\/[a-zA-Z0-9\-\._~:\/\?#\[\]@!$&\'\(\)\*\+,;=]*)?$'  # path, query, fragment
    )
    return bool(url_pattern.match(url))

def is_valid_proxy_url(proxy_url):
    """
    Check if a proxy URL is valid.
    
    Args:
        proxy_url (str): Proxy URL to check.
    
    Returns:
        bool: True if the proxy URL is valid, False otherwise.
    """
    if not proxy_url:
        return False
    
    # Simple regex to validate proxy URL format
    proxy_pattern = re.compile(
        r'^(https?|socks5):\/\/'  # http://, https://, or socks5://
        r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|localhost|([0-9]{1,3}\.){3}[0-9]{1,3}'  # domain or IP
        r'(\:[0-9]{1,5})$'  # port (required)
    )
    return bool(proxy_pattern.match(proxy_url)) 