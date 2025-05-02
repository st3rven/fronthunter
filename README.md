# FrontHunter

FrontHunter is a tool for testing large lists of domains to identify candidates for domain fronting.

## Domain Fronting? Really?

I know, I know… domain fronting is pretty old. But the truth is, it’s still useful as just another feature to include in your C2 infrastructure. When it comes to domains, there are still plenty of good candidates out there. ;)

## Features

- Test lists of domains for domain fronting capability
- Multi-threaded checks for faster processing
- Customizable HTTP request parameters (headers, timeout, etc.)
- Support for proxy usage
- Content-based verification
- Detailed result reporting

## Installation

```bash
# Clone the repository
git clone https://github.com/st3rven/fronthunter.git
cd fronthunter

# Install dependencies
pip3 install -r requirements.txt
```

## Usage

### Examples

Test a single domain:
```bash
python fronthunter.py -c example.com --front-domain target.com
```

Test multiple domains from a file:
```bash
python fronthunter.py -f domains.txt --front-domain target.com
```

Use a proxy for testing:
```bash
python fronthunter.py -c example.com --front-domain target.com --http-proxy http://proxy.example.com:8080
```

Save results to a file:
```bash
python fronthunter.py -c example.com --front-domain target.com -o results.json --output-format json
```

## Options

### Mode Selection
- `-c, --check DOMAIN`: Check a single domain
- `-f, --file FILE`: Check domains from a file

### Domain Fronting Check Options
- `-t, --threads THREADS`: Number of threads to use (default: 10)
- `--timeout TIMEOUT`: Timeout in seconds for HTTP requests (default: 10)
- `--delay DELAY`: Delay in milliseconds between requests (default: 0)
- `--user-agent USER_AGENT`: User-Agent header to use
- `--front-domain FRONT_DOMAIN`: Domain to use in Host header
- `--http-proxy HTTP_PROXY`: HTTP proxy to use
- `--https-proxy HTTPS_PROXY`: HTTPS proxy to use
- `--verify-ssl`: Verify SSL certificates (default: False)
- `--port PORT`: Port to connect to (default: 443)
- `--expected-content EXPECTED_CONTENT`: Content to expect in the response
- `--expected-status EXPECTED_STATUS`: HTTP status code to expect

### Output Options
- `-o, --output OUTPUT`: Output file to save results
- `--output-format {txt,csv,json}`: Output format (default: txt)
- `--log-file LOG_FILE`: Log file to save verbose output
- `--quiet`: Suppress console output except for errors

## Contributing

Contributions are welcome! 

The truth is, this is a tool I built quite a while ago, and I only recently decided to release it publicly. That said, I won’t be addressing minor bugs that get reported, so, please feel free to submit a PR.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details. 
