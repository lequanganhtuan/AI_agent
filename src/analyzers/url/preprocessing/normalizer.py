import hashlib

from urllib.parse import (
    urlparse,
    parse_qsl,
    urlencode,
    urlunparse
)

class URLNormalizer:
    # Versioning the cache key format to easily invalidate old caches in the future
    CACHE_VERSION = "v1"
    
    def normalize(self, url: str) -> str:
        """
        Standardizes a given URL into a consistent format.
        This ensures different representations of the same URL yield the identical string.
        """
        parsed = urlparse(url)
        # URL schemes and hostnames are case-insensitive, so convert them to lowercase
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        
        # Remove standard default ports to avoid duplicate URL variations
        if (
            (scheme == "http" and port == 80)
            or
            (scheme == "https" and port == 443)
        ):
            netloc = hostname # Strip the port if it is the default
        else:
            netloc = parsed.netloc.lower() # Keep the custom port if it's non-standard
        
        # Convert query string into a list of tuples and sort them alphabetically
        # Example: ?z=1&a=2 becomes [('a', '2'), ('z', '1')]
        query_pairs = sorted(parse_qsl(parsed.query))
        # Re-encode the sorted query pairs back into a standardized query string
        normalized_query = urlencode(query_pairs)
        # Clean up the path (handling trailing slashes consistently)
        path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
        normalized_url = urlunparse(
            (
                scheme,
                netloc,
                path,
                "", # Stripping generic params component
                normalized_query,
                "" # Stripping URL fragments (the '#' part)
            )
        )
        
        return normalized_url
    
    def build_cache_key(self, normalized_url: str) -> str:
        """
        Generates a unique, fixed-length cache key using SHA-256 hashing.
        Prevents long or unsafe URL characters from breaking the cache storage system.
        """
        # Convert string to bytes and generate a 64-character hexadecimal SHA-256 hash
        digest = hashlib.sha256(
            normalized_url.encode("utf-8")
        ).hexdigest()
        # Return the final structured key combined with the cache version prefix
        return f"url:{self.CACHE_VERSION}:{digest}"
    