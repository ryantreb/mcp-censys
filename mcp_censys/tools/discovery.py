"""
Censys MCP tools module

This module defines Claude-compatible tools that use the Censys Platform API to
perform recon on domains and IPs through natural language interactions.
"""

from datetime import datetime, timedelta, timezone
from collections import defaultdict
from mcp_censys.client.censys import CensysClient, _extract_hits, _extract_total
from mcp.server.fastmcp import FastMCP
import mcp.types as types
import sys
import logging

mcp = FastMCP("Censys MCP Server")
censys = CensysClient()


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def is_domain_match(hostname: str, domain: str) -> bool:
    """
    Check if a hostname matches or is a subdomain of the given domain.

    Args:
        hostname: The hostname to check
        domain: The domain to check against

    Returns:
        bool: True if hostname matches domain or is a subdomain
    """
    hostname = hostname.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    return hostname == domain or hostname.endswith(f".{domain}")


@mcp.prompt(
    name="Lookup Domain",
    description="Create an insightful analysis of basic domain infrastructure.",
)
def lookup_domain_prompt(domain: str) -> str:
    """
    Create a prompt template for basic domain lookup with intelligent analysis.

    Args:
        domain: The domain to lookup

    Returns:
        str: A prompt template for Claude to summarize domain information
    """
    return f"""
        # {domain} - Infrastructure Analysis

        Perform a lookup_domain on `{domain}` ONLY - do not run any additional tools.

        Create an intelligent analysis that identifies patterns and organizes the data into meaningful sections.

        ## Suggested Sections
        - **Infrastructure Overview**: A brief summary of the domain's hosting approach
        - **IP Distribution**: Analyze the IP addresses and their organization
        - **DNS Architecture**: Identify naming patterns and DNS structure
        - **Service Configuration**: Examine the services and ports in use
        - **Network Presence**: Analyze the ASNs and hosting providers

        ## Technical Data Requirements
        - Display up to 5 IPv4 addresses in a code block, with total count in parentheses
        - Only report the count of IPv6 addresses (do not list them)
        - Include up to 5 forward DNS entries and 5 reverse DNS entries with total counts
        - List all observed open ports
        - Include all ASN information

        ## Guidelines
        1. Run ONLY the lookup_domain tool - no additional lookups
        2. Group similar information and identify patterns
        3. Use code blocks for technical data that might need to be copied
        4. DO NOT make claims about infrastructure quality or suggest improvements
        5. Organize information based on logical relationships in the data
        6. Keep your analysis factual while highlighting interesting patterns
    """


@mcp.prompt(
    name="Lookup Domain (Detailed)",
    description="Create an intelligent analysis of domain infrastructure.",
)
def lookup_domain_detailed_prompt(domain: str) -> str:
    """
    Create a prompt template for detailed domain lookup with intelligent analysis.

    Args:
        domain: The domain to lookup in detail

    Returns:
        str: A prompt template for Claude to summarize detailed domain information
    """
    return f"""
        # {domain} - Infrastructure Analysis

        Perform a lookup_domain_detailed on `{domain}` and create a comprehensive analysis Do not run any additional tools

        Begin with the sample limitation note from the response data, then analyze the infrastructure by grouping similar information into meaningful sections.

        ## Required Sections
        - **Infrastructure Overview**: A brief summary of the overall hosting approach
        - **IP Addresses**: List all IPs in an easy-to-copy code block
        - **DNS Information**: Include reverse DNS entries in a code block, identify any naming patterns
        - **Geographic Distribution**: Analyze where servers are located
        - **Technical Configuration**: Group common technical elements (ASNs, services, OS)
        - **Content Delivery Architecture**: Identify the hosting/CDN strategy

        ## Technical Data Format
        Present IPs and DNS entries in code blocks for easy copying:

        ```
        IP Addresses:
        ip_address_1
        ip_address_2
        ```

        ```
        Reverse DNS:
        dns_name_1
        dns_name_2
        ```

        ## Important Guidelines
        1. Group similar data rather than listing each host separately
        2. Identify patterns and commonalities across all hosts
        3. ALWAYS include a dedicated section for IPs and DNS entries in code blocks
        4. DO NOT make claims about infrastructure "quality" or "maintenance schedules"
        5. Present timestamps as observation timestamps only, not maintenance indicators
        6. Include significant details but avoid creating an overwhelming report
    """


@mcp.tool(
    description="Summarize a domain's infrastructure: IPs, reverse DNS names, open ports, and ASNs."
)
async def lookup_domain(domain: str) -> dict:
    """
    Lookup a domain's infrastructure information from Censys.

    Retrieves IP addresses, DNS names, ASNs, and open ports associated with a domain
    by searching Censys for matches in DNS records.

    Args:
        domain: The domain to lookup

    Returns:
        dict: A dictionary containing domain infrastructure information
    """
    logger.info(f"Looking up domain infrastructure: {domain}")

    query = f"(dns.names: {domain} OR dns.reverse_dns.names: {domain})"
    fields = [
        "ip",
        "dns.names",
        "dns.reverse_dns.names",
        "autonomous_system.name",
        "services.port",
    ]

    # Initialize sets to collect all data
    ips, dns_names, reverse_dns, asns, ports = set(), set(), set(), set(), set()

    logger.info(f"Searching Censys for hosts related to {domain}")
    response = censys.search(query, fields, page_size=100)
    hits = _extract_hits(response)

    for r in hits:
        if ip := r.get("ip"):
            ips.add(ip)
        dns = r.get("dns", {})
        dns_names.update(dns.get("names", []))
        reverse_dns.update(dns.get("reverse_dns", {}).get("names", []))
        if asn := r.get("autonomous_system", {}).get("name"):
            asns.add(asn)
        ports.update(s.get("port") for s in r.get("services", []) if s.get("port"))

    logger.info(f"Found {len(hits)} records for {domain}")
    logger.info(
        f"Collected {len(ips)} IPs, {len(dns_names)} DNS names, {len(reverse_dns)} reverse DNS names"
    )

    return {
        "domain": domain,
        "ips": sorted(ips),
        "dns_names": sorted(dns_names),
        "reverse_dns": sorted(reverse_dns),
        "asns": sorted(asns),
        "ports": sorted(ports),
    }


@mcp.tool(
    description="Return full host records for a domain (services, ASN, geo, TLS). Shows a limited sample of matching records."
)
async def lookup_domain_detailed(domain: str) -> dict:
    """
    Lookup detailed host records for a domain from Censys.

    Returns full host records including services, ASN, geo, and TLS information.
    To avoid overwhelming the user, only returns a limited sample of records.

    Args:
        domain: The domain to lookup

    Returns:
        dict: A dictionary containing detailed host records
    """
    logger.info(f"Looking up detailed domain information: {domain}")

    query = f"(dns.names: {domain} OR dns.reverse_dns.names: {domain})"
    per_page = 3  # Limit to just 3 records

    logger.info(f"Performing search for {domain} with sample limit of {per_page}")
    response = censys.search(query, page_size=per_page)

    hits = _extract_hits(response)
    total_records = _extract_total(response)

    logger.info(f"Found {total_records} total records for {domain}")

    # Create an informative note about available records
    if total_records > per_page:
        note = f"Showing {len(hits)} of {total_records} total records. There are {total_records - per_page} additional records not displayed."
    else:
        note = f"Showing all {total_records} record(s)."

    return {
        "domain": domain,
        "record_count": total_records,
        "sample_limit": per_page,
        "note": note,
        "records": hits,
    }


@mcp.tool(
    description="Get full metadata for an IP: DNS, ASN, ports, TLS, and location."
)
async def lookup_ip(ip: str) -> dict:
    """
    Lookup detailed metadata for an IP address from Censys.

    Retrieves full IP metadata including DNS, ASN, geographical location,
    open ports, services, and TLS certificate information.

    Args:
        ip: The IP address to lookup

    Returns:
        dict: A dictionary containing IP metadata
    """
    logger.info(f"Looking up IP metadata: {ip}")

    host_data = censys.get_host(ip)

    # Extract the host result from the response
    result = host_data.get("result", host_data)

    logger.info(f"Retrieved host data for IP: {ip}")

    return {"ip": ip, "host": result}


@mcp.tool(description="Find recently seen FQDNs tied to a domain in DNS and certs.")
async def new_fqdns(
    domain: str,
    days: int = 1,
) -> dict:
    """
    Find recently seen FQDNs (fully qualified domain names) tied to a domain.

    Searches both DNS records and certificates in Censys to find domain names
    that have been seen within the specified time period.

    Args:
        domain: The base domain to search for
        days: Number of days back to search (default: 1)

    Returns:
        dict: A dictionary containing recently seen FQDNs and their sources
    """
    logger.info(
        f"Searching for recently seen FQDNs for domain: {domain} (last {days} days)"
    )

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    fqdns = defaultdict(lambda: {"sources": set(), "last_seen": None})

    # Search for DNS records in hosts
    dns_query = f"(dns.names: {domain} OR dns.reverse_dns.names: {domain}) AND last_updated_at: [{since} TO *]"

    logger.info(f"Searching DNS records since {since}")
    dns_response = censys.search(dns_query, page_size=100)
    dns_hits = _extract_hits(dns_response)

    for r in dns_hits:
        last_seen = r.get("last_updated_at")
        dns_data = r.get("dns", {})
        for name in dns_data.get("names", []):
            if is_domain_match(name, domain):
                fqdns[name]["sources"].add("hosts-dns")
                fqdns[name]["last_seen"] = last_seen
        for name in dns_data.get("reverse_dns", {}).get("names", []):
            if is_domain_match(name, domain):
                fqdns[name]["sources"].add("hosts-reverse")
                fqdns[name]["last_seen"] = last_seen

    logger.info(
        f"Found {len(dns_hits)} DNS records with {len(fqdns)} matching FQDNs"
    )

    # Search for certificates mentioning this domain
    cert_query = f"names: {domain} AND added_at: [{since} TO *]"

    logger.info(f"Searching certificates since {since}")
    cert_response = censys.search(cert_query, page_size=100)
    cert_hits = _extract_hits(cert_response)

    for r in cert_hits:
        added_at = r.get("added_at")
        for name in r.get("names", []):
            if is_domain_match(name, domain):
                fqdns[name]["sources"].add("certs")
                fqdns[name]["last_seen"] = added_at

    logger.info(f"Found {len(cert_hits)} certificates with matching domains")
    logger.info(f"Total unique FQDNs found: {len(fqdns)}")

    return {
        "domain": domain,
        "days": days,
        "new_fqdns": sorted(fqdns.keys()),
        "count": len(fqdns),
        "details": {
            name: {
                "sources": sorted(list(data["sources"])),
                "last_seen": data["last_seen"],
            }
            for name, data in fqdns.items()
        },
    }


@mcp.tool(description="List exposed ports and service names for a given IP address.")
async def host_services(ip: str) -> dict:
    """
    List exposed ports and service names for a given IP address.

    Uses the Censys get_host endpoint for direct IP lookup instead of search,
    providing more complete and efficient results.

    Args:
        ip: The IP address to lookup

    Returns:
        dict: A dictionary containing services running on the IP
    """
    logger.info(f"Looking up services for IP: {ip}")

    host_data = censys.get_host(ip)
    result = host_data.get("result", host_data)

    services = []
    for s in result.get("services", []):
        services.append(
            {
                "port": s.get("port"),
                "service": s.get("service_name"),
                "transport_protocol": s.get("transport_protocol"),
            }
        )

    logger.info(f"Found {len(services)} services for IP: {ip}")

    return {"ip": ip, "services": services}


__all__ = ["mcp"]
