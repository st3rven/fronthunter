#!/usr/bin/env python3

import requests
from requests.exceptions import RequestException, ConnectionError, Timeout, TooManyRedirects, SSLError
import time
import re
import logging
import socket
from urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('fronthunter')

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def perform_domain_fronting_check(domain, target, user_agent, timeout=10.0, verbose=False, 
                                  retry_count=2, verify_ssl=True, proxies=None, 
                                  expected_content=None):

    result = {
        "domain": domain,
        "target": target,
        "success": False,
        "status_code": None,
        "response_time": None,
        "error": None,
        "error_type": None,
        "verification_method": None,
        "retry_count": 0,
        "using_proxy": bool(proxies),
        "content_verification": None
    }
    
    url = f"https://{domain}"
    headers = {
        "Host": target,
        "User-Agent": user_agent,
        # Add Connection: close to prevent persistent connection issues
        "Connection": "close"
    }
    
    if verbose:
        proxy_info = f" via proxy" if proxies else ""
        print(f"Checking {domain} -> {target}{proxy_info}")
    
    if not is_valid_domain(domain):
        result["error"] = f"Invalid domain format: {domain}"
        result["error_type"] = "InvalidDomain"
        logger.warning(f"Invalid domain format: {domain}")
        return result
    
    if not proxies:
        try:
            socket.gethostbyname(domain)
        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {str(e)}"
            result["error_type"] = "DNSError"
            if verbose:
                print(f"DNS resolution failed for {domain}: {e}")
            logger.warning(f"DNS resolution failed for {domain}: {e}")
            return result
    
    for attempt in range(retry_count + 1):
        try:
            start_time = time.time()
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout, 
                allow_redirects=False,
                verify=verify_ssl,
                proxies=proxies
            )
            end_time = time.time()
            
            result["status_code"] = response.status_code
            result["response_time"] = round(end_time - start_time, 3)
            result["response_headers"] = dict(response.headers)
            result["retry_count"] = attempt
            
            if expected_content:
                response_content = response.text
                result["response_excerpt"] = response_content[:200] + "..." if len(response_content) > 200 else response_content
            
            fronting_verification = verify_domain_fronting(
                response, 
                domain, 
                target, 
                expected_content=expected_content
            )
            result["success"] = fronting_verification["success"]
            result["verification_method"] = fronting_verification["method"]
            result["verification_details"] = fronting_verification["details"]
            
            break
            
        except ConnectionError as e:
            result["error"] = f"Connection error: {str(e)}"
            result["error_type"] = "ConnectionError"
            logger.debug(f"Connection error on attempt {attempt+1}/{retry_count+1} for {domain}: {e}")
            
        except Timeout as e:
            result["error"] = f"Request timed out: {str(e)}"
            result["error_type"] = "Timeout"
            logger.debug(f"Timeout on attempt {attempt+1}/{retry_count+1} for {domain}: {e}")
            
        except SSLError as e:
            result["error"] = f"SSL error: {str(e)}"
            result["error_type"] = "SSLError"
            logger.debug(f"SSL error on attempt {attempt+1}/{retry_count+1} for {domain}: {e}")
            
            if attempt == retry_count - 1 and verify_ssl:
                logger.info(f"Retrying {domain} without SSL verification")
                try:
                    start_time = time.time()
                    response = requests.get(
                        url, 
                        headers=headers, 
                        timeout=timeout, 
                        allow_redirects=False,
                        verify=False,
                        proxies=proxies
                    )
                    end_time = time.time()
                    
                    result["status_code"] = response.status_code
                    result["response_time"] = round(end_time - start_time, 3)
                    result["response_headers"] = dict(response.headers)
                    result["retry_count"] = attempt + 1
                    result["ssl_verified"] = False
                    
                    fronting_verification = verify_domain_fronting(
                        response, 
                        domain, 
                        target, 
                        expected_content=expected_content
                    )
                    result["success"] = fronting_verification["success"]
                    result["verification_method"] = fronting_verification["method"]
                    result["verification_details"] = fronting_verification["details"]
                    
                    break
                    
                except RequestException as e2:
                    result["error"] = f"Request failed (SSL bypass): {str(e2)}"
                    result["error_type"] = "SSLBypassError"
                    
        except TooManyRedirects as e:
            result["error"] = f"Too many redirects: {str(e)}"
            result["error_type"] = "TooManyRedirects"
            logger.debug(f"Too many redirects on attempt {attempt+1}/{retry_count+1} for {domain}: {e}")
            break
            
        except RequestException as e:
            result["error"] = f"Request failed: {str(e)}"
            result["error_type"] = "RequestException"
            logger.debug(f"Request failed on attempt {attempt+1}/{retry_count+1} for {domain}: {e}")
        
        if attempt < retry_count:
            backoff_time = 0.5 * (2 ** attempt)  # 0.5, 1, 2, 4, ... seconds
            time.sleep(backoff_time)
    
    if verbose and result.get("error"):
        print(f"Error checking {domain}: {result['error']}")
    
    return result


def is_valid_domain(domain):
    """Check if a domain name is valid."""
    if not domain:
        return False
    
    # Allows domains like example.com, sub.example.com, etc.
    domain_pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    
    # Also allow IP addresses
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    return bool(domain_pattern.match(domain) or ip_pattern.match(domain))


def verify_domain_fronting(response, original_domain, target_domain, expected_content=None):

    verification = {
        "success": False,
        "method": None,
        "details": {}
    }
    
    if expected_content and response.text:
        if expected_content in response.text:
            verification["success"] = True
            verification["method"] = "content_match"
            verification["details"]["content_match"] = True
            verification["details"]["expected_content"] = expected_content
            return verification
        else:
            verification["details"]["content_match"] = False
            verification["details"]["expected_content"] = expected_content
    
    if 200 <= response.status_code < 300:
        if expected_content and verification["details"].get("content_match") is False:
            verification["details"]["status_code"] = response.status_code
            verification["details"]["status_code_ok"] = True
        else:
            verification["success"] = True
            verification["method"] = "direct_success"
            verification["details"]["status_code"] = response.status_code
            return verification
    
    if 300 <= response.status_code < 400 and "Location" in response.headers:
        redirect_url = response.headers["Location"]
        verification["details"]["redirect_url"] = redirect_url
        
        redirect_domain = extract_domain_from_url(redirect_url)
        verification["details"]["redirect_domain"] = redirect_domain
        
        if redirect_domain and (
            redirect_domain == target_domain or 
            redirect_domain.endswith(f".{target_domain}") or
            target_domain in redirect_domain
        ):
            verification["success"] = True
            verification["method"] = "redirect_to_target"
            return verification
    
    server_headers = ["Server", "X-Served-By", "X-Server", "Via"]
    for header in server_headers:
        if header in response.headers and target_domain in response.headers[header].lower():
            verification["success"] = True
            verification["method"] = f"server_header_{header.lower()}"
            verification["details"][f"header_{header}"] = response.headers[header]
            return verification
    
    cdn_signatures = identify_cdn_from_headers(response.headers)
    verification["details"]["identified_cdn"] = cdn_signatures
    
    if cdn_signatures and target_domain in " ".join(cdn_signatures).lower():
        verification["success"] = True
        verification["method"] = "cdn_signature"
        return verification
    
    return verification


def extract_domain_from_url(url):
    """Extract the domain from a URL."""
    if not url:
        return None
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    try:
        match = re.search(r'https?://([^/]+)', url)
        if match:
            return match.group(1)
    except Exception:
        pass
    
    return None


def identify_cdn_from_headers(headers):
    identified_cdns = []
    
    # Check for Akamai
    if any(h in headers for h in ['X-Akamai-Transformed', 'X-Akamai-SSL-Client-IP']):
        identified_cdns.append('Akamai')
    
    # Check for Cloudflare
    if 'cf-ray' in headers or 'cf-cache-status' in headers:
        identified_cdns.append('Cloudflare')
    
    # Check for Fastly
    if 'x-served-by' in headers and 'cache-' in headers.get('x-served-by', '').lower():
        identified_cdns.append('Fastly')
    
    # Check for Azure CDN
    if any(h.startswith('x-azure-') for h in headers) or 'x-msedge-ref' in headers:
        identified_cdns.append('Azure CDN')
    
    # Check for CloudFront
    if 'x-amz-cf-id' in headers or 'x-amz-cf-pop' in headers:
        identified_cdns.append('CloudFront')
    
    # Check for Google Cloud CDN
    if 'x-goog-' in " ".join(headers.keys()):
        identified_cdns.append('Google Cloud CDN')
    
    return identified_cdns


def check_domain_response(domain, user_agent, timeout=10.0, retry_count=1, verify_ssl=True, proxies=None):
    result = {
        "domain": domain,
        "available": False,
        "status_code": None,
        "error": None,
        "error_type": None,
        "retry_count": 0,
        "using_proxy": bool(proxies)
    }
    
    if not is_valid_domain(domain):
        result["error"] = f"Invalid domain format: {domain}"
        result["error_type"] = "InvalidDomain"
        return result
    
    url = f"https://{domain}"
    headers = {
        "User-Agent": user_agent,
        "Connection": "close"
    }
    
    for attempt in range(retry_count + 1):
        try:
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout,
                verify=verify_ssl,
                proxies=proxies
            )
            
            result["status_code"] = response.status_code
            result["available"] = True
            result["retry_count"] = attempt

            cdn_info = identify_cdn_from_headers(response.headers)
            if cdn_info:
                result["cdn_info"] = cdn_info
                
            break
                
        except ConnectionError as e:
            result["error"] = f"Connection error: {str(e)}"
            result["error_type"] = "ConnectionError"
            
        except Timeout as e:
            result["error"] = f"Request timed out: {str(e)}"
            result["error_type"] = "Timeout"
            
        except SSLError as e:
            result["error"] = f"SSL error: {str(e)}"
            result["error_type"] = "SSLError"
            
            if attempt == retry_count and verify_ssl:
                try:
                    response = requests.get(
                        url, 
                        headers=headers, 
                        timeout=timeout,
                        verify=False,
                        proxies=proxies
                    )
                    
                    result["status_code"] = response.status_code
                    result["available"] = True
                    result["retry_count"] = attempt + 1
                    result["ssl_verified"] = False
                    
                    cdn_info = identify_cdn_from_headers(response.headers)
                    if cdn_info:
                        result["cdn_info"] = cdn_info
                        
                except RequestException as e2:
                    result["error"] = f"Request failed (SSL bypass): {str(e2)}"
                    result["error_type"] = "SSLBypassError"
            
        except RequestException as e:
            result["error"] = f"Request failed: {str(e)}"
            result["error_type"] = "RequestException"
        
        # Sleep before retrying (exponential backoff)
        if attempt < retry_count:
            backoff_time = 0.5 * (2 ** attempt)
            time.sleep(backoff_time)
    
    return result 