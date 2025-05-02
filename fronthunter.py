#!/usr/bin/env python3

import os
import sys
import time
import signal
import argparse
import logging
import random
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress
from rich.panel import Panel
from rich.text import Text

from utils.validators import is_valid_domain, is_valid_ip, is_valid_port
from utils.checkers import check_domain_fronting

# Import utility modules
from utils.http_client import perform_domain_fronting_check
from utils.threading import get_optimal_thread_count, RateLimiter, ThreadPoolWithRateLimiting
from utils.result_processor import process_and_display_results, save_results_to_file

# Define banner
BANNER = """
    ███████╗██████╗  ██████╗ ███╗   ██╗████████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔════╝██╔══██╗██╔═══██╗████╗  ██║╚══██╔══╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    █████╗  ██████╔╝██║   ██║██╔██╗ ██║   ██║   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══╝  ██╔══██╗██║   ██║██║╚██╗██║   ██║   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                    Domain Fronting Tester - https://github.com/st3rven/fronthunter
"""

console = Console()
shutdown_event = None
progress = None

def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="FrontHunter - Tool for checking candidates to domain fronting",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-c", "--check",
        metavar="DOMAIN",
        help="Check a single domain"
    )
    mode_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="Check domains from a file"
    )
    
    check_group = parser.add_argument_group("Domain Fronting Check Options")
    check_group.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of threads to use (default: 10)"
    )
    check_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout in seconds for HTTP requests (default: 10)"
    )
    check_group.add_argument(
        "--delay",
        type=int,
        default=0,
        help="Delay in milliseconds between requests (default: 0)"
    )
    check_group.add_argument(
        "--user-agent",
        help="User-Agent header to use for HTTP requests"
    )
    check_group.add_argument(
        "--front-domain",
        help="Domain to use in Host header (instead of target domain)"
    )
    check_group.add_argument(
        "--http-proxy",
        help="HTTP proxy to use (format: http://ip:port)"
    )
    check_group.add_argument(
        "--https-proxy",
        help="HTTPS proxy to use (format: https://ip:port)"
    )
    check_group.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (default: False)"
    )
    check_group.add_argument(
        "--port",
        type=int,
        default=443,
        help="Port to connect to for HTTPS requests (default: 443)"
    )
    check_group.add_argument(
        "--expected-content",
        help="Content to expect in the response to consider fronting successful"
    )
    check_group.add_argument(
        "--expected-status",
        type=int,
        help="HTTP status code to expect in the response (default: 2xx)"
    )
    
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        help="Output file to save results"
    )
    output_group.add_argument(
        "--output-format",
        choices=["txt", "csv", "json"],
        default="txt",
        help="Output format (default: txt)"
    )
    output_group.add_argument(
        "--log-file",
        help="Log file to save verbose output"
    )
    output_group.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output except for errors"
    )
    
    return parser.parse_args()

def read_domains_from_file(file_path):
    """Read domains from file, one domain per line."""
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Error: File '{file_path}' not found")
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        print(f"Error reading file: {e}")
        sys.exit(1)

def read_expected_content(file_path):
    """Read expected content from file."""
    try:
        with open(file_path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        logger.error(f"Error: Content file '{file_path}' not found")
        print(f"Error: Content file '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading content file: {e}")
        print(f"Error reading content file: {e}")
        sys.exit(1)

def setup_logging(debug=False, log_file=None):
    """Configure logging based on debug flag."""
    log_level = logging.DEBUG if debug else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler() if debug else logging.NullHandler(),
            logging.FileHandler(log_file or 'fronthunter.log')
        ]
    )
    
    logger = logging.getLogger('fronthunter')
    logger.setLevel(log_level)
    
    if logger.hasHandlers():
        logger.handlers.clear()
    
    if debug:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter('%(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    file_handler = logging.FileHandler(log_file or 'fronthunter.log')
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger

def handle_interrupt(signum, frame):
    """Handle interrupt signals (Ctrl+C) for graceful shutdown."""
    global shutdown_event
    
    if shutdown_event:
        console.print("\n[bold red]Forced shutdown![/bold red]")
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        return
        
    shutdown_event = True
    console.print("\n[yellow]Shutting down gracefully... Press Ctrl+C again to force exit.[/yellow]")
    
def shutdown_executor():
    """Shutdown the thread executor gracefully."""
    global executor
    
    if executor:
        logger.info("Shutting down thread executor...")
        executor.shutdown(wait=False)
        time.sleep(1)
        logger.info("Thread executor shutdown initiated")

def create_rate_limiter(args):
    """
    Create a rate limiter based on command line arguments.
    
    Returns:
        RateLimiter or None if no rate limiting is requested
    """
    if not any([args.requests_per_second, args.requests_per_minute, args.requests_per_hour]):
        return None
        
    try:
        limiter = RateLimiter(
            requests_per_second=args.requests_per_second,
            requests_per_minute=args.requests_per_minute,
            requests_per_hour=args.requests_per_hour,
            burst_size=args.burst_size,
            distribute_evenly=args.distribute_evenly
        )
        
        logger.info(f"Rate limiter enabled: {limiter.rate_per_second:.2f} req/sec, "
                   f"burst size: {limiter.burst_size}")
        
        if args.verbose:
            print(f"Rate limiting enabled: {limiter.rate_per_second:.2f} requests/second")
            
        return limiter
    except ValueError as e:
        logger.error(f"Error creating rate limiter: {e}")
        print(f"Error: {e}")
        sys.exit(1)

def run_with_graceful_shutdown(func, *args, **kwargs):
    """
    Run a function with graceful shutdown handling.
    
    Args:
        func: Function to run.
        *args: Arguments to pass to the function.
        **kwargs: Keyword arguments to pass to the function.
        
    Returns:
        The result of the function.
    """
    global shutdown_event
    
    shutdown_event = False
    
    original_sigint = signal.getsignal(signal.SIGINT)
    original_sigterm = signal.getsignal(signal.SIGTERM)
    
    def signal_handler(signum, frame):
        """Signal handler for graceful shutdown."""
        global shutdown_event
        
        if shutdown_event:
            console.print("\n[bold red]Forced shutdown![/bold red]")
            signal.signal(signal.SIGINT, original_sigint)
            signal.signal(signal.SIGTERM, original_sigterm)
            return
            
        shutdown_event = True
        console.print("\n[yellow]Shutting down gracefully... Press Ctrl+C again to force exit.[/yellow]")
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        result = func(*args, **kwargs)
        return result
    finally:
        signal.signal(signal.SIGINT, original_sigint)
        signal.signal(signal.SIGTERM, original_sigterm)

def check_domains_for_fronting(domains, threads=10, timeout=10, delay=0, user_agent=None, 
                              front_domain=None, proxies=None, verify_ssl=False, 
                              port=443, output_file=None, output_format="txt", expected_content=None, 
                              expected_status=None, quiet=False):
    """
    Check a list of domains for domain fronting capability.
    
    Args:
        domains (list): List of domains to check.
        threads (int): Number of threads to use.
        timeout (int): Timeout in seconds for HTTP requests.
        delay (int): Delay in milliseconds between requests.
        user_agent (str): User-Agent header to use.
        front_domain (str): Domain to use in Host header.
        proxies (dict): Proxies to use for HTTP requests.
        verify_ssl (bool): Whether to verify SSL certificates.
        port (int): Port to connect to for HTTPS requests.
        output_file (str): Output file to save results.
        output_format (str): Output format.
        expected_content (str): Content to expect in response.
        expected_status (int): HTTP status code to expect.
        quiet (bool): Whether to suppress console output.
        
    Returns:
        list: List of results.
    """
    global shutdown_event
    
    return check_domain_fronting(
        domains=domains,
        threads=threads,
        timeout=timeout,
        delay=delay,
        user_agent=user_agent,
        front_domain=front_domain,
        proxies=proxies,
        verify_ssl=verify_ssl,
        port=port,
        output_file=output_file,
        output_format=output_format,
        expected_content=expected_content,
        expected_status=expected_status,
        quiet=quiet
    )

def main():
    """Main function for FrontHunter."""
    global console
    
    args = parse_arguments()
    
    setup_logging(args.verbose, args.log_file)
    logger = logging.getLogger('fronthunter')
    
    if not args.quiet:
        console.print(Panel.fit(BANNER, border_style="blue"))
        console.print()
    
    try:
        proxies = {}
        if args.http_proxy:
            proxies['http'] = args.http_proxy
        if args.https_proxy:
            proxies['https'] = args.https_proxy
        
        if args.check:
            if not is_valid_domain(args.check):
                logger.error(f"Invalid domain: {args.check}")
                console.print(f"[bold red]Error:[/bold red] Invalid domain: {args.check}")
                return 1
            
            domains = [args.check]
            logger.info(f"Checking single domain: {args.check}")
            
        elif args.file:
            domains = read_domains_from_file(args.file)
            if not domains:
                logger.error(f"No valid domains found in file: {args.file}")
                console.print(f"[bold red]Error:[/bold red] No valid domains found in file: {args.file}")
                return 1
            
            logger.info(f"Loaded {len(domains)} domains from file: {args.file}")
            if not args.quiet:
                console.print(f"Loaded [bold]{len(domains)}[/bold] domains from file: {args.file}")
        
        else:
            logger.error("No mode specified")
            console.print("[bold red]Error:[/bold red] No mode specified")
            return 1
            
        if len(domains) > 1000 and not args.quiet:
            console.print(f"[bold yellow]Warning:[/bold yellow] You are about to check {len(domains)} domains, which may take a while.")
            proceed = Prompt.ask(
                "Do you want to proceed?",
                choices=["y", "n"],
                default="y"
            )
            
            if proceed.lower() != "y":
                return 0
        
        run_with_graceful_shutdown(
            check_domains_for_fronting,
            domains=domains,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent,
            front_domain=args.front_domain,
            proxies=proxies,
            verify_ssl=args.verify_ssl,
            port=args.port,
            output_file=args.output,
            output_format=args.output_format,
            expected_content=args.expected_content,
            expected_status=args.expected_status,
            quiet=args.quiet
        )
        
        return 0
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        console.print("\n[bold yellow]Interrupted by user[/bold yellow]")
        return 1
    
    except Exception as e:
        logger.exception(f"Unexpected error: {str(e)}")
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 