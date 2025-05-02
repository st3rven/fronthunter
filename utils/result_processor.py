#!/usr/bin/env python3

import json
import csv
import sys
from datetime import datetime
from tabulate import tabulate


def process_and_display_results(results, output_format="table"):

    if not results:
        print("No results to display.")
        return
    
    successful = [r for r in results if r.get("success", False)]
    
    print("\n" + "="*60)
    print(f"CHECK RESULTS")
    print("="*60)
    print(f"Total domains checked: {len(results)}")
    print(f"Successful domain fronting: {len(successful)} ({len(successful)/len(results)*100:.1f}%)")
    print(f"Failed domain fronting: {len(results) - len(successful)} ({(len(results) - len(successful))/len(results)*100:.1f}%)")
    print("="*60 + "\n")
    
    if output_format == "json":
        display_results_as_json(results)
    elif output_format == "detailed":
        display_detailed_results(results)
    else:  # Default to table format
        display_results_as_table(results)


def display_results_as_table(results):
    table_data = []
    headers = ["Domain", "Target", "Status", "Status Code", "Response Time (s)"]
    
    for result in results:
        status = "✓" if result.get("success", False) else "✗"
        
        row = [
            result.get("domain", "N/A"),
            result.get("target", "N/A"),
            status,
            result.get("status_code", "N/A"),
            result.get("response_time", "N/A")
        ]
        table_data.append(row)
    
    table_data.sort(key=lambda x: x[2], reverse=True)
    
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print()


def display_results_as_json(results):
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total": len(results),
            "successful": sum(1 for r in results if r.get("success", False)),
            "failed": sum(1 for r in results if not r.get("success", False))
        },
        "results": results
    }
    
    # Print formatted JSON to console
    print(json.dumps(output_data, indent=2))
    print()


def display_detailed_results(results):
    display_results_as_table(results)
    
    failed_results = [r for r in results if not r.get("success", False)]
    if failed_results:
        print("\n" + "="*60)
        print("DETAILED ERROR INFORMATION")
        print("="*60)
        
        for result in failed_results:
            domain = result.get("domain", "unknown")
            target = result.get("target", "unknown")
            
            print(f"\nDomain: {domain} -> {target}")
            print(f"Status Code: {result.get('status_code', 'N/A')}")
            print(f"Error Type: {result.get('error_type', 'Unknown')}")
            print(f"Error: {result.get('error', 'No specific error message')}")
            
            if "verification_details" in result:
                print("Verification Details:")
                for key, value in result["verification_details"].items():
                    print(f"  {key}: {value}")
            
            if "response_headers" in result:
                print("Response Headers:")
                for key, value in result["response_headers"].items():
                    print(f"  {key}: {value}")
            
            print("-" * 40)
    
    error_types = {}
    for result in failed_results:
        error_type = result.get("error_type", "Unknown")
        if error_type not in error_types:
            error_types[error_type] = 0
        error_types[error_type] += 1
    
    if error_types:
        print("\nError Type Summary:")
        for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {error_type}: {count} occurrences")
    
    print()


def save_results_to_file(results, output_file, format=None):
    if not results:
        return
    
    if format == "json" or (not format and output_file.lower().endswith('.json')):
        save_as_json(results, output_file)
    elif format == "csv" or (not format and output_file.lower().endswith('.csv')):
        save_as_csv(results, output_file)
    else:
        save_as_json(results, output_file)


def save_as_json(results, output_file):
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "results": results,
        "summary": {
            "total": len(results),
            "successful": sum(1 for r in results if r.get("success", False)),
            "failed": sum(1 for r in results if not r.get("success", False))
        }
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
    except Exception as e:
        print(f"Error saving JSON results to file: {e}", file=sys.stderr)


def save_as_csv(results, output_file):
    fields = [
        "domain", "target", "success", "status_code", "response_time", 
        "error", "error_type", "verification_method", "retry_count"
    ]
    
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for result in results:
                filtered_result = {k: v for k, v in result.items() if k in fields}
                writer.writerow(filtered_result)
    except Exception as e:
        print(f"Error saving CSV results to file: {e}", file=sys.stderr)


def generate_error_report(results, output_file=None):
    failed_results = [r for r in results if not r.get("success", False)]
    
    if not failed_results:
        print("No failed checks to report.")
        return
    
    errors_by_type = {}
    for result in failed_results:
        error_type = result.get("error_type", "Unknown")
        if error_type not in errors_by_type:
            errors_by_type[error_type] = []
        errors_by_type[error_type].append(result)
    
    report = ["DOMAIN FRONTING ERROR REPORT", "=" * 80, ""]
    report.append(f"Timestamp: {datetime.now().isoformat()}")
    report.append(f"Total checks: {len(results)}")
    report.append(f"Failed checks: {len(failed_results)} ({len(failed_results)/len(results)*100:.1f}%)")
    report.append("")
    
    report.append("ERROR SUMMARY BY TYPE")
    report.append("-" * 40)
    for error_type, errors in sorted(errors_by_type.items(), key=lambda x: len(x[1]), reverse=True):
        report.append(f"{error_type}: {len(errors)} occurrences ({len(errors)/len(failed_results)*100:.1f}% of failures)")
    
    report.append("\nDETAILED ERROR INFORMATION")
    report.append("=" * 80)
    
    for error_type, errors in errors_by_type.items():
        report.append(f"\n{error_type} ERRORS ({len(errors)} occurrences)")
        report.append("-" * 60)
        
        for i, result in enumerate(errors[:10]):  # Limit to 10 examples per type
            domain = result.get("domain", "unknown")
            target = result.get("target", "unknown")
            
            report.append(f"\nExample {i+1}: {domain} -> {target}")
            report.append(f"  Status Code: {result.get('status_code', 'N/A')}")
            report.append(f"  Error: {result.get('error', 'No specific error message')}")
            
            if "verification_details" in result:
                report.append("  Verification Details:")
                for key, value in result["verification_details"].items():
                    report.append(f"    {key}: {value}")
        
        if len(errors) > 10:
            report.append(f"\n... and {len(errors) - 10} more similar errors")
    
    report_text = "\n".join(report)
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"Error report saved to {output_file}")
        except Exception as e:
            print(f"Error saving error report to file: {e}", file=sys.stderr)
    else:
        print(report_text) 