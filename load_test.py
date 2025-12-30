#!/usr/bin/env python3
"""
External Load Testing Script for HTTP Lookup Service

This script performs real HTTP load testing against the server
using asyncio and httpx for concurrent requests.

Usage:
    python load_test.py --requests 1000 --concurrency 100
    python load_test.py -r 5000 -c 500
"""

import asyncio
import httpx
import time
import argparse
from collections import defaultdict


async def make_request(client, url, stats):
    """Make a single HTTP request and track stats"""
    start_time = time.time()
    try:
        response = await client.get(url)
        duration = time.time() - start_time
        
        stats['total'] += 1
        stats['success'] += 1
        stats['status_codes'][response.status_code] += 1
        stats['response_times'].append(duration)
        
        return {'success': True, 'status': response.status_code, 'duration': duration}
    except Exception as e:
        duration = time.time() - start_time
        stats['total'] += 1
        stats['errors'] += 1
        stats['response_times'].append(duration)
        return {'success': False, 'error': str(e), 'duration': duration}


async def run_load_test(base_url, total_requests, concurrency):
    """Run the load test with specified parameters"""
    
    # Test URLs to cycle through
    test_urls = [
        f"{base_url}/urlinfo/1/example.com/test",
        f"{base_url}/urlinfo/1/malicious-site.com/download",
        f"{base_url}/urlinfo/1/google.com/search?q=test",
        f"{base_url}/urlinfo/1/phishing-bank.com/login",
        f"{base_url}/urlinfo/1/safe-domain.org/page",
    ]
    
    stats = {
        'total': 0,
        'success': 0,
        'errors': 0,
        'status_codes': defaultdict(int),
        'response_times': []
    }
    
    print(f"\n🚀 Starting Load Test")
    print(f"{'='*60}")
    print(f"Target: {base_url}")
    print(f"Total Requests: {total_requests:,}")
    print(f"Concurrency: {concurrency}")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    
    # Create HTTP client with connection pooling
    async with httpx.AsyncClient(
        timeout=30.0,
        limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    ) as client:
        
        # Create tasks in batches to control concurrency
        for batch_start in range(0, total_requests, concurrency):
            batch_size = min(concurrency, total_requests - batch_start)
            
            tasks = [
                make_request(client, test_urls[i % len(test_urls)], stats)
                for i in range(batch_start, batch_start + batch_size)
            ]
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Print progress
            progress = (batch_start + batch_size) / total_requests * 100
            elapsed = time.time() - start_time
            current_rps = (batch_start + batch_size) / elapsed if elapsed > 0 else 0
            print(f"Progress: {progress:5.1f}% | {batch_start + batch_size:,}/{total_requests:,} | {current_rps:,.1f} req/s", end='\r')
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Calculate statistics
    avg_response_time = sum(stats['response_times']) / len(stats['response_times']) if stats['response_times'] else 0
    min_response_time = min(stats['response_times']) if stats['response_times'] else 0
    max_response_time = max(stats['response_times']) if stats['response_times'] else 0
    
    # Sort response times for percentile calculation
    sorted_times = sorted(stats['response_times'])
    p50_idx = int(len(sorted_times) * 0.50)
    p95_idx = int(len(sorted_times) * 0.95)
    p99_idx = int(len(sorted_times) * 0.99)
    
    p50 = sorted_times[p50_idx] if sorted_times else 0
    p95 = sorted_times[p95_idx] if sorted_times else 0
    p99 = sorted_times[p99_idx] if sorted_times else 0
    
    # Print results
    print(f"\n\n✅ Load Test Complete!")
    print(f"{'='*60}")
    print(f"Duration: {duration:.2f}s")
    print(f"Total Requests: {stats['total']:,}")
    print(f"Successful: {stats['success']:,} ({stats['success']/stats['total']*100:.1f}%)")
    print(f"Failed: {stats['errors']:,} ({stats['errors']/stats['total']*100:.1f}%)")
    print(f"\n📊 Performance Metrics:")
    print(f"Requests/Second: {stats['total']/duration:,.2f}")
    print(f"Avg Response Time: {avg_response_time*1000:.2f}ms")
    print(f"Min Response Time: {min_response_time*1000:.2f}ms")
    print(f"Max Response Time: {max_response_time*1000:.2f}ms")
    print(f"P50 Response Time: {p50*1000:.2f}ms")
    print(f"P95 Response Time: {p95*1000:.2f}ms")
    print(f"P99 Response Time: {p99*1000:.2f}ms")
    
    print(f"\n📈 Status Code Distribution:")
    for code, count in sorted(stats['status_codes'].items()):
        print(f"  {code}: {count:,} ({count/stats['total']*100:.1f}%)")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(description='Load test the HTTP Lookup Service')
    parser.add_argument('-r', '--requests', type=int, default=1000, help='Total number of requests (default: 1000)')
    parser.add_argument('-c', '--concurrency', type=int, default=100, help='Number of concurrent requests (default: 100)')
    parser.add_argument('--url', type=str, default='http://localhost:8000', help='Base URL of the server (default: http://localhost:8000)')
    
    args = parser.parse_args()
    
    try:
        asyncio.run(run_load_test(args.url, args.requests, args.concurrency))
    except KeyboardInterrupt:
        print("\n\n⚠️  Load test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")


if __name__ == '__main__':
    main()
