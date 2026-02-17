"""
CensysClient wrapper for the Censys Platform API.

Uses the censys-platform SDK with Personal Access Token (PAT) authentication.
PATs replace the legacy API ID + Secret pair.

Environment variables required:
  - CENSYS_PAT: Personal Access Token from https://search.censys.io/account/api
"""

import os
from dotenv import load_dotenv
from censys_platform import SDK

# Load credentials from .env file
load_dotenv()

CENSYS_PAT = os.getenv("CENSYS_PAT")

if not CENSYS_PAT:
    raise EnvironmentError(
        "CENSYS_PAT must be set in environment variables. "
        "Get your token at https://search.censys.io/account/api"
    )


class CensysClient:
    def __init__(self):
        """Initialize the Censys Platform SDK with PAT credentials."""
        self.sdk = SDK(personal_access_token=CENSYS_PAT)

    def search(self, query: str, fields: list = None, page_size: int = 10) -> dict:
        """
        Execute a search query against Censys global data.

        Args:
            query (str): Censys Search Language query string
            fields (list): List of fields to return in results
            page_size (int): Number of results per page (max 100)

        Returns:
            dict: Response containing 'hits' list and metadata
        """
        body = {"query": query, "page_size": page_size}
        if fields:
            body["fields"] = fields
        response = self.sdk.global_data.search(search_query_input_body=body)
        return _to_dict(response)

    def get_host(self, ip: str) -> dict:
        """
        Get full metadata for a specific host by IP address.

        Args:
            ip (str): The IP address to lookup

        Returns:
            dict: Complete host metadata including services, DNS, ASN, geo
        """
        response = self.sdk.global_data.get_host(ip=ip)
        return _to_dict(response)


def _to_dict(obj) -> dict:
    """Convert SDK response object to a plain dict."""
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    return {}


def _extract_hits(response: dict) -> list:
    """
    Extract hit results from a search response dict.

    Handles multiple response structures the SDK may return:
      - {"result": {"hits": [...]}}
      - {"hits": [...]}
      - {"result": {"query": {...}, "hits": [...]}}
    """
    if "result" in response:
        result = response["result"]
        if isinstance(result, dict) and "hits" in result:
            return result["hits"]
    if "hits" in response:
        return response["hits"]
    return []


def _extract_total(response: dict) -> int:
    """Extract total record count from a search response."""
    if "result" in response:
        result = response["result"]
        if isinstance(result, dict):
            return result.get("total", 0)
    return response.get("total", 0)
