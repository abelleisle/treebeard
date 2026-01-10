#!/usr/bin/env python3
"""
Fast DNS Query Script
Uses asyncio and dnspython for high-performance DNS queries.
"""

import asyncio
import argparse
import sys
import time
from typing import Optional
from dataclasses import dataclass

try:
    import dns.asyncresolver
    import dns.resolver
    import dns.rdatatype
except ImportError:
    print("Error: dnspython not installed. Run: pip install dnspython")
    sys.exit(1)


@dataclass
class QueryResult:
    domain: str
    record_type: str
    answers: list[str]
    query_time_ms: float
    error: Optional[str] = None


async def query_dns(
    domain: str,
    record_type: str = "A",
    nameserver: Optional[str] = None,
    port: int = 53,
    timeout: float = 2.0,
) -> QueryResult:
    """Query DNS for a single domain."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout

    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.port = port

    start = time.perf_counter()
    try:
        answer = await resolver.resolve(domain, record_type)
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(
            domain=domain,
            record_type=record_type,
            answers=[rdata.to_text() for rdata in answer],
            query_time_ms=elapsed,
        )
    except dns.resolver.NXDOMAIN:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(domain, record_type, [], elapsed, "NXDOMAIN")
    except dns.resolver.NoAnswer:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(domain, record_type, [], elapsed, "No answer")
    except dns.resolver.Timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(domain, record_type, [], elapsed, "Timeout")
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return QueryResult(domain, record_type, [], elapsed, str(e))


async def bulk_query(
    domains: list[str],
    record_type: str = "A",
    nameserver: Optional[str] = None,
    port: int = 53,
    timeout: float = 2.0,
    concurrency: int = 100,
) -> list[QueryResult]:
    """Query multiple domains concurrently with rate limiting."""
    semaphore = asyncio.Semaphore(concurrency)

    async def limited_query(domain: str) -> QueryResult:
        async with semaphore:
            return await query_dns(domain, record_type, nameserver, port, timeout)

    tasks = [limited_query(d.strip()) for d in domains if d.strip()]
    return await asyncio.gather(*tasks)


def print_results(results: list[QueryResult], verbose: bool = False) -> None:
    """Print query results."""
    for r in results:
        if r.error:
            print(f"{r.domain}: {r.error}")
        else:
            answers = ", ".join(r.answers)
            if verbose:
                print(
                    f"{r.domain} [{r.record_type}] -> {answers} ({r.query_time_ms:.2f}ms)"
                )
            else:
                print(f"{r.domain}: {answers}")


async def main():
    parser = argparse.ArgumentParser(
        description="Fast DNS query tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s google.com                    # Query A record
  %(prog)s google.com -t MX              # Query MX records
  %(prog)s -f domains.txt                # Bulk query from file
  %(prog)s -f domains.txt -c 200         # 200 concurrent queries
  %(prog)s google.com -n 8.8.8.8         # Use specific nameserver
  %(prog)s google.com -n 8.8.8.8 -p 5353 # Use custom port
        """,
    )
    parser.add_argument("domains", nargs="*", help="Domain(s) to query")
    parser.add_argument(
        "-t",
        "--type",
        default="A",
        help="Record type (A, AAAA, MX, TXT, NS, CNAME, etc.)",
    )
    parser.add_argument(
        "-n", "--nameserver", help="DNS server to query (e.g., 8.8.8.8)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=53, help="DNS server port (default: 53)"
    )
    parser.add_argument("-f", "--file", help="File containing domains (one per line)")
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=100,
        help="Max concurrent queries (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Query timeout in seconds (default: 2.0)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show query times")
    parser.add_argument("-o", "--output", help="Output file for results")

    args = parser.parse_args()

    # Collect domains
    domains = list(args.domains) if args.domains else []
    if args.file:
        try:
            with open(args.file) as f:
                domains.extend(
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                )
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not domains:
        parser.print_help()
        sys.exit(1)

    # Run queries
    start = time.perf_counter()
    results = await bulk_query(
        domains,
        record_type=args.type.upper(),
        nameserver=args.nameserver,
        port=args.port,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )
    total_time = time.perf_counter() - start

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            for r in results:
                if r.error:
                    f.write(f"{r.domain}\t{r.error}\n")
                else:
                    f.write(f"{r.domain}\t{','.join(r.answers)}\n")
        print(f"Results written to {args.output}")
    else:
        print_results(results, args.verbose)

    # Summary
    if args.verbose or len(domains) > 1:
        successful = sum(1 for r in results if not r.error)
        print(
            f"\n--- {len(domains)} queries in {total_time:.2f}s ({len(domains) / total_time:.1f} queries/sec) ---"
        )
        print(f"Success: {successful}, Failed: {len(domains) - successful}")


if __name__ == "__main__":
    asyncio.run(main())
