#!/usr/bin/env python3

import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, TaskID
from rich.console import Console

import requests

from utils.validators import is_valid_domain

logger = logging.getLogger('fronthunter')

def check_domain_fronting(domains, threads=10, timeout=10, delay=0, user_agent=None, 
                         front_domain=None, proxies=None, verify_ssl=False, 
                         port=443, output_file=None, output_format="txt", expected_content=None, 
                         expected_status=None, quiet=False):

    if not expected_content:
        raise ValueError("expected_content is required for domain fronting validation")
        
    console = Console()
    results = []
    
    if not domains:
        logger.error("No domains to check")
        if not quiet:
            console.print("[bold red]Error:[/bold red] No domains to check")
        return results
    
    if not quiet:
        console.print(f"[bold]Checking {len(domains)} domains for fronting capability...[/bold]")
        
    with Progress(
        "[progress.description]{task.description}",
        "[progress.percentage]{task.percentage:>3.0f}%",
        "•",
        "{task.completed}/{task.total}",
        "•",
        "[progress.elapsed]{task.elapsed}",
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[green]Testing domains...", total=len(domains))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for domain in domains:
                future = executor.submit(
                    perform_check,
                    domain=domain,
                    front_domain=front_domain or domain,
                    timeout=timeout,
                    user_agent=user_agent,
                    proxies=proxies,
                    verify_ssl=verify_ssl,
                    port=port,
                    expected_content=expected_content,
                    expected_status=expected_status
                )
                futures[future] = domain
                
                if delay > 0:
                    time.sleep(delay / 1000.0)
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        if not quiet:
                            if result.get("fronting_successful", False):
                                console.print(f"[green]✓[/green] {domain} - Fronting successful")
                            else:
                                error = result.get("error", "Unknown error")
                                console.print(f"[red]✗[/red] {domain} - {error}")
                except Exception as e:
                    logger.error(f"Error checking {domain}: {e}")
                    results.append({
                        "domain": domain,
                        "front_domain": front_domain or domain,
                        "fronting_successful": False,
                        "error": str(e),
                        "error_type": "UnexpectedException",
                        "headers": {}
                    })
                progress.update(task, advance=1)
    
    if not quiet:
        successful = sum(1 for r in results if r.get("fronting_successful", False))
        console.print(f"\n[bold]Results:[/bold] {successful}/{len(domains)} domains support fronting")
        
    if output_file:
        from utils.result_processor import save_results_to_file
        save_results_to_file(results, output_file, output_format)
        if not quiet:
            console.print(f"Results saved to [bold]{output_file}[/bold]")
    
    return results

def perform_check(domain, front_domain, timeout=10, user_agent=None, proxies=None, 
                 verify_ssl=False, port=443, expected_content=None, expected_status=None):

    if not expected_content:
        raise ValueError("expected_content is required for domain fronting validation")
        
    if not is_valid_domain(domain):
        return {
            "domain": domain,
            "front_domain": front_domain,
            "fronting_successful": False,
            "error": "Invalid domain",
            "error_type": "InvalidDomain"
        }
    
    result = {
        "domain": domain,
        "front_domain": front_domain,
        "fronting_successful": False,
        "timestamp": time.time(),
        "response_time": None,
        "status_code": None,
        "content_length": None,
        "headers": None
    }
    
    try:
        headers = {
            "Host": front_domain,
            "User-Agent": user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        url = f"https://{domain}:{port}/"
        
        start_time = time.time()
        response = requests.get(
            url,
            headers=headers,
            proxies=proxies,
            verify=verify_ssl,
            timeout=timeout,
            allow_redirects=False
        )
        end_time = time.time()
        
        result["response_time"] = end_time - start_time
        result["status_code"] = response.status_code
        result["content_length"] = len(response.content)
        result["headers"] = dict(response.headers)
        
        if expected_status and response.status_code != expected_status:
            result["error"] = f"Expected status {expected_status}, got {response.status_code}"
            result["error_type"] = "StatusMismatch"
            return result
        
        if expected_content and expected_content not in response.text:
            result["error"] = f"Expected content not found in response"
            result["error_type"] = "ContentMismatch"
            return result
        
        if not expected_status and not expected_content and 200 <= response.status_code < 300:
            result["fronting_successful"] = True

        elif (expected_status and response.status_code == expected_status) or \
             (expected_content and expected_content in response.text):
            result["fronting_successful"] = True
        else:
            result["error"] = f"Status code {response.status_code} not in 2xx range"
            result["error_type"] = "UnexpectedStatus"
        
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        result["error_type"] = "Timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection error"
        result["error_type"] = "ConnectionError"
    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects"
        result["error_type"] = "TooManyRedirects"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        result["error_type"] = "RequestException"
    except Exception as e:
        result["error"] = str(e)
        result["error_type"] = "UnexpectedException"
    
    return result 