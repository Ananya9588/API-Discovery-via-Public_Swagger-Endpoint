#!/usr/bin/env python3
"""
Swagger API Detector using Python Requests
Converts Nuclei template logic to pure Python using requests library.
Detects Public Swagger API endpoints without needing Nuclei.
"""

import argparse
import sys
import re
import json
import urllib3
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, TimeoutError, FIRST_COMPLETED
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Dict, List, Tuple, Optional, Any
import time
import signal

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
    HAS_BEAUTIFULSOUP = True
except ImportError:
    HAS_BEAUTIFULSOUP = False
SWAGGER_PATHS = [
    "/swagger-ui/swagger-ui.js",
    "/swagger-ui/index.html",
    "/swagger/swagger-ui.js",
    "/swagger-ui.js",
    "/swagger/ui/swagger-ui.js",
    "/swagger/ui/index",
    "/swagger/index.html",
    "/swagger-ui.html",
    "/swagger/swagger-ui.html",
    "/api/swagger-ui.html",
    "/api-docs/swagger.json",
    "/api-docs/swagger.yaml",
    "/api_docs",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v1/swagger.yaml",
    "/api/index.html",
    "/api/doc",
    "/api/docs/",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/swagger.yml",
    "/api/swagger/index.html",
    "/api/swagger/swagger-ui.html",
    "/api/api-docs/swagger.json",
    "/api/api-docs/swagger.yaml",
    "/api/swagger-ui/swagger.json",
    "/api/swagger-ui/swagger.yaml",
    "/api/apidocs/swagger.json",
    "/api/apidocs/swagger.yaml",
    "/api/v1/swagger.json",
    "/api/v1/swagger.yaml",
    "/swagger/v2/swagger.json",
    "/swagger/v2/swagger.yaml",
    "/docs/swagger.json",
    "/docs/swagger.yaml",
    "/service/swagger.json",
    "/v1/swagger.json",
    "/v1/swagger.yaml",
    "/v1/api-docs/swagger.json",
    "/v1/swagger",
    "/v2/swagger.json",
    "/v2/swagger.yaml",
    "/v2/api-docs/swagger.json",
    "/v2/swagger",
    "/v3/swagger.json",
    "/v3/swagger.yaml",
    "/rpc/swagger.json",
    "/rest/swagger.json",
    "/swagger",
    "/v2/api-docs",
    "/api",
    "/index.html",
]

# Swagger keywords to match in response body
SWAGGER_KEYWORDS = [
    "swagger:",
    "Swagger 2.0",
    "\"swagger\":",
    "Swagger UI",
    "loadSwaggerUI",
    "**token**:",
    "id=\"swagger-ui",
    "\"swagger\": \"",  # Matches "swagger": "X.0" pattern
]

# Version regex from template
VERSION_REGEX = re.compile(r"@version (v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")


def create_session_with_retries(retries=3):
    """Create a requests session with retry strategy"""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def check_swagger_matchers(status_code, body):
    """
    Check if response matches Swagger matchers (matchers-condition: or)
    1. Status 200
    2. Status 401 with 'authentication' in body
    3. Any swagger keyword in body
    """
    # Matcher 1: Status 200
    if status_code == 200:
        return True
    
    # Matcher 2: Status 401 with authentication error
    if status_code == 401 and "authentication" in body.lower():
        return True
    
    # Matcher 3: Swagger keywords in body
    for keyword in SWAGGER_KEYWORDS:
        if keyword.lower() in body.lower():
            return True
    
    return False


def has_swagger_ui(body):
    """
    Check if response contains "Swagger UI" or swagger JSON content
    Detects:
    - HTML pages with Swagger UI interface
    - JSON swagger specs with "swagger": "X.Y" or "swagger": X.Y
    """
    # Check for Swagger UI HTML interface
    if "Swagger UI" in body or "swagger-ui" in body.lower():
        return True
    
    # Check for swagger JSON content (pure swagger spec)
    # Match "swagger": "2.0" or "swagger": 2.0 patterns
    swagger_pattern = re.compile(r'"swagger"\s*:\s*["\']?[\d.]+["\']?', re.IGNORECASE)
    if swagger_pattern.search(body):
        return True
    
    return False


def extract_version(body):
    """Extract version from response body using regex"""
    match = VERSION_REGEX.search(body)
    if match:
        return match.group(1)
    return None


# ========== HTML Parsing Functions (from swagger-html.py) ==========

def join_full(base: str, path: str) -> Optional[str]:
    """Join base URL with path"""
    if not base:
        return None
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def dedupe(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove duplicate endpoints"""
    seen, out = set(), []
    for r in rows:
        key = (r.get("method", ""), r.get("path", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def parse_openapi_spec(spec: Dict[str, Any], spec_url: str = "") -> List[Dict[str, str]]:
    """Parse OpenAPI/Swagger specification and extract endpoints
    spec_url: optional URL to spec file for constructing full URLs when spec lacks servers
    """
    out = []
    
    if "openapi" in spec:  # OpenAPI 3.x
        servers = [s.get("url", "") for s in (spec.get("servers") or []) if isinstance(s, dict)]
        base = servers[0] if servers else ""
        
        # If no servers defined and we have spec URL, derive base from it
        if not base and spec_url:
            parsed = urlparse(spec_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path, ops in (spec.get("paths") or {}).items():
            if not isinstance(ops, dict):
                continue
            for method, op in ops.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"):
                    continue
                summary = (op or {}).get("summary", "") or (op or {}).get("operationId", "") or ""
                tags = (op or {}).get("tags") or []
                tag = tags[0] if tags else ""
                full = join_full(base, path)
                out.append({
                    "method": method.upper(),
                    "path": path,
                    "full_url": full or "",
                    "tag": tag,
                    "summary": summary
                })
    elif "swagger" in spec:  # Swagger 2.0
        scheme = (spec.get("schemes") or ["https"])[0]
        host = spec.get("host", "")
        bp = spec.get("basePath", "") or ""
        base = f"{scheme}://{host}{bp}" if host else ""
        
        # If no host defined and we have spec URL, derive base from it
        if not host and spec_url:
            parsed = urlparse(spec_url)
            base = f"{parsed.scheme}://{parsed.netloc}{bp}"
        
        for path, ops in (spec.get("paths") or {}).items():
            if not isinstance(ops, dict):
                continue
            for method, op in ops.items():
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"):
                    continue
                summary = (op or {}).get("summary", "") or (op or {}).get("operationId", "") or ""
                tags = (op or {}).get("tags") or []
                tag = tags[0] if tags else ""
                full = join_full(base, path)
                out.append({
                    "method": method.upper(),
                    "path": path,
                    "full_url": full or "",
                    "tag": tag,
                    "summary": summary
                })
    
    return dedupe(out)


def parse_from_aria(label: str) -> Tuple[str, str]:
    """Parse method and path from aria-label"""
    s = re.sub(r"&ZeroWidthSpace;|&#8203;|\u200B", "", label or "", flags=re.IGNORECASE)
    m = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\b\s+(\S+)", s, re.I)
    return (m.group(1).upper(), m.group(2)) if m else ("", "")


def extract_swagger_spec_url_from_html(html: str, base_url: str) -> Optional[str]:
    """
    Extract swagger spec URL from Swagger UI HTML configuration.
    Looks for SwaggerUIBundle configuration or data attributes with spec URLs.
    Returns absolute URL to swagger spec.
    """
    # Pattern 1: Look for configObject with urls array
    config_pattern = r'var\s+configObject\s*=\s*JSON\.parse\s*\(\s*["\']({[^"\']*})["\']'
    match = re.search(config_pattern, html, re.IGNORECASE | re.DOTALL)
    
    if match:
        try:
            config_str = match.group(1)
            # Unescape JSON string
            config_str = config_str.replace('\\"', '"')
            config = json.loads(config_str)
            
            # Check for urls array
            if "urls" in config and isinstance(config["urls"], list) and len(config["urls"]) > 0:
                spec_url = config["urls"][0].get("url", "")
                if spec_url:
                    # Convert relative URLs to absolute
                    if spec_url.startswith("http"):
                        return spec_url
                    elif spec_url.startswith("/"):
                        # Absolute path
                        parsed = urlparse(base_url)
                        return f"{parsed.scheme}://{parsed.netloc}{spec_url}"
                    else:
                        # Relative path
                        return urljoin(base_url, spec_url)
        except Exception:
            pass
    
    # Pattern 2: Look for url: "..." pattern
    url_pattern = r'["\']url["\']?\s*:\s*["\']([^"\']+)["\']'
    matches = re.findall(url_pattern, html, re.IGNORECASE)
    for match in matches:
        if "swagger" in match.lower() or "api" in match.lower() or match.endswith((".json", ".yaml")):
            if match.startswith("http"):
                return match
            elif match.startswith("/"):
                parsed = urlparse(base_url)
                return f"{parsed.scheme}://{parsed.netloc}{match}"
            else:
                return urljoin(base_url, match)
    
    # Pattern 3: Look for spec URLs in data attributes
    spec_pattern = r'["\']([^"\']*(?:swagger|spec|api)[^"\']*\.(?:json|yaml|yml))["\']'
    matches = re.findall(spec_pattern, html, re.IGNORECASE)
    for match in matches:
        if match.startswith("http"):
            return match
        elif match.startswith("/"):
            parsed = urlparse(base_url)
            return f"{parsed.scheme}://{parsed.netloc}{match}"
        else:
            return urljoin(base_url, match)
    
    return None


def scrape_html_for_endpoints(html: str, base_url: str = "", session=None, timeout: float = 5) -> Tuple[Optional[str], List[Dict[str, str]]]:
    """
    Scrape HTML Swagger UI page for endpoints.
    First tries to extract spec URL from HTML config and fetch it directly.
    Falls back to DOM scraping if spec URL not found.
    Returns (server_base, list of endpoints)
    """
    # Try to extract swagger spec URL from HTML configuration
    spec_url = extract_swagger_spec_url_from_html(html, base_url)
    
    if spec_url and session:
        try:
            response = session.get(
                spec_url,
                timeout=timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if response.status_code == 200:
                try:
                    spec = response.json()
                    # Pass spec_url so parse_openapi_spec can use it for base URL
                    endpoints = parse_openapi_spec(spec, spec_url)
                    # Extract server base from spec
                    server_base = ""
                    if "openapi" in spec:
                        servers = [s.get("url", "") for s in (spec.get("servers") or []) if isinstance(s, dict)]
                        server_base = servers[0] if servers else ""
                    elif "swagger" in spec:
                        scheme = (spec.get("schemes") or ["https"])[0]
                        host = spec.get("host", "")
                        bp = spec.get("basePath", "") or ""
                        if host:
                            server_base = f"{scheme}://{host}{bp}"
                    
                    # Fallback: use spec URL base if no server defined
                    if not server_base and spec_url:
                        parsed = urlparse(spec_url)
                        server_base = f"{parsed.scheme}://{parsed.netloc}"
                    
                    return server_base, endpoints
                except Exception:
                    pass
        except requests.RequestException:
            pass
    
    # Fallback: Try DOM scraping for rendered Swagger UI pages
    if not HAS_BEAUTIFULSOUP:
        return None, []
    
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return None, []
    
    base = None
    sel = soup.select_one(".servers select option[selected]") or soup.select_one(".servers select option")
    if sel and sel.text.strip():
        base = sel.text.strip()

    rows = []
    for op in soup.select(".opblock"):
        method = ""
        path = ""
        
        method_el = op.select_one(".opblock-summary-method")
        if method_el:
            method = method_el.text.strip().upper()
        
        p_el = op.select_one(".opblock-summary-path")
        if p_el:
            if p_el.has_attr("data-path"):
                path = p_el.get("data-path")
            else:
                path = p_el.text.strip()
        
        # Fallback to aria-label
        if not method or not path:
            btn = op.select_one('button[aria-label]')
            if btn:
                m, pa = parse_from_aria(btn.get("aria-label", ""))
                method = method or m
                path = path or pa
        
        if not method or not path:
            continue
        
        tag = ""
        parent_tag = op.find_parent(class_="opblock-tag-section")
        if parent_tag:
            h = parent_tag.select_one("h4.opblock-tag")
            if h:
                tag = " ".join(h.text.split())
        
        desc_el = op.select_one(".opblock-summary-description")
        summary = " ".join(desc_el.text.split()) if desc_el else ""
        
        rows.append({
            "method": method,
            "path": path,
            "full_url": join_full(base, path) or "",
            "tag": tag,
            "summary": summary
        })
    
    return base, dedupe(rows)


def extract_api_endpoints(response, target_url):
    """
    Parse Swagger/OpenAPI JSON response and extract all API endpoints.
    response: requests.Response object containing Swagger/OpenAPI JSON
    target_url: the original target URL (for fallback base URL)
    returns: list of dicts with method, endpoint, full_endpoint
    """
    try:
        spec = response.json()
    except:
        return []

    # Get base components from spec, or fallback to target URL
    scheme = spec.get("schemes", ["https"])[0] if spec.get("schemes") else "https"
    host = spec.get("host", "")
    base_path = spec.get("basePath", "").rstrip("/") if spec.get("basePath") else ""

    # If host is missing, extract from target URL
    if not host:
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.netloc
        # If basePath is also missing, use path from target as base
        if not base_path and parsed.path != "/" and not parsed.path.endswith(".json") and not parsed.path.endswith(".yaml"):
            base_path = parsed.path.rstrip("/")

    endpoints = []

    for endpoint, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            if method.lower() in {"get", "post", "put", "delete", "patch", "options", "head"}:
                full_endpoint = f"{scheme}://{host}{base_path}{endpoint}"
                endpoints.append({
                    "method": method.upper(),
                    "endpoint": endpoint,
                    "full_endpoint": full_endpoint
                })

    return endpoints


def check_swagger_endpoint(target, path, session, timeout=10):
    """
    Check a single swagger path for a target.
    Returns (found, url, version, endpoints) or (False, None, None, []) if not found.
    Extracts API endpoints from JSON swagger specs or HTML Swagger UI pages.
    """
    url = urljoin(target, path)
    
    try:
        response = session.get(
            url,
            timeout=timeout,
            verify=False,
            headers={
                "Accept": "*/*",
                "User-Agent": "Mozilla/5.0"
            },
            allow_redirects=True
        )
        body = response.text
        
        # Check matchers AND ensure response contains "Swagger UI"
        if check_swagger_matchers(response.status_code, body) and has_swagger_ui(body):
            version = extract_version(body)
            
            # Try to extract API endpoints
            endpoints = []
            content_type = response.headers.get("Content-Type", "").lower()
            
            # If JSON response, parse as OpenAPI/Swagger spec
            if "application/json" in content_type or body.strip().startswith("{"):
                try:
                    endpoints = extract_api_endpoints(response, url)
                except:
                    pass
            
            # If HTML response, scrape Swagger UI page (don't make extra requests during timeout)
            if not endpoints and ("text/html" in content_type or "<html" in body.lower() or "<!doctype" in body.lower()):
                try:
                    # Only parse local DOM, don't make additional requests when under time pressure
                    if HAS_BEAUTIFULSOUP:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(body, "html.parser")
                        # Check if this is a Swagger UI page by looking for swagger-ui elements
                        if soup.find(id="swagger-ui") or soup.find(class_="swagger-ui"):
                            # Return the page itself as an endpoint
                            endpoints = []
                    else:
                        # If BeautifulSoup not available, still report the page as a swagger endpoint
                        endpoints = []
                except Exception:
                    pass
            
            return True, url, version, endpoints
            
    except requests.RequestException:
        pass
    
    return False, None, None, []


def scan_target(target, session, max_workers=10):
    """
    Scan a single target for swagger endpoints.
    Returns list of found swagger endpoints with their API endpoints.
    """
    target = target.strip()
    if not target:
        return []
    
    # Ensure target has scheme
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    found_endpoints = []
    
    # Use ThreadPoolExecutor for concurrent path checking
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_swagger_endpoint, target, path, session): path
            for path in SWAGGER_PATHS
        }
        
        for future in as_completed(futures):
            found, url, version, endpoints = future.result()
            if found:
                found_endpoints.append({
                    "target": target,
                    "endpoint": url,
                    "version": version,
                    "api_endpoints": endpoints
                })
    
    return found_endpoints


def main():
    parser = argparse.ArgumentParser(
        description="Detect Swagger API endpoints using Python requests (Nuclei-template based)"
    )
    parser.add_argument(
        "-tf", "--targets-file",
        help="Path to file containing list of target URLs (one per line)."
    )
    parser.add_argument(
        "-u", "--url",
        help="Single target URL to scan."
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads per target (default: 10)"
    )
    parser.add_argument(
        "--target-threads",
        type=int,
        default=5,
        help="Number of concurrent threads for scanning multiple targets (default: 5)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds for each target scan (default: 60)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.targets_file and not args.url:
        parser.print_help()
        print("\n❌ Error: Please provide either -tf (targets file) or -u (single URL)")
        sys.exit(1)
    
    # Get targets
    targets = []
    if args.url:
        targets = [args.url]
    else:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"❌ Error: File not found: {args.targets_file}")
            sys.exit(1)
    
    if not targets:
        print("❌ Error: No targets provided")
        sys.exit(1)
    
    # Global variables for signal handler
    global active_targets, completed_count
    active_targets = set()
    completed_count = [0]  # Use list to allow modification
    
    def signal_handler(sig, frame):
        """Handle SIGINT (Ctrl+C) to show current progress"""
        print(f"\n\n⚠️  Scan interrupted!")
        print(f"📊 Progress: {completed_count[0]}/{len(targets)} targets completed")
        if active_targets:
            print(f"🔄 Currently processing {len(active_targets)} target(s):")
            for target in sorted(active_targets):
                print(f"   • {target}")
        else:
            print("🔄 No targets currently being processed")
        print(f"⏱️  Total scan time: {time.time() - total_start_time:.1f}s")
        sys.exit(130)
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    total_start_time = time.time()
    print(f"[*] Scanning {len(targets)} target(s) for Swagger endpoints...")
    print(f"[*] Testing {len(SWAGGER_PATHS)} paths per target")
    print(f"[*] Timeout per target: {args.timeout} seconds")
    print(f"[*] Target threads: {args.target_threads}, Path threads per target: {args.threads}")
    print("💡 Press Ctrl+C to see current progress and exit gracefully\n")
    
    all_results = []
    active_targets = set()  # Track currently processing targets
    
    # Function to scan a single target (for threading)
    def scan_target_with_timeout(target):
        active_targets.add(target)
        if not args.json:
            print(f"[*] Starting scan for {target}")
        session = create_session_with_retries()
        try:
            start_time = time.time()
            found_endpoints = []
            timed_out = False
            
            def check_endpoint_with_timeout(path):
                """Check a single endpoint with timeout"""
                # Hard stop: check wall-clock time
                if (time.time() - start_time) >= args.timeout:
                    return False, None, None, []
                
                remaining_time = args.timeout - (time.time() - start_time)
                # Use minimum timeout to ensure we never exceed target timeout
                request_timeout = min(1.0, max(0.2, remaining_time * 0.7))
                try:
                    return check_swagger_endpoint(target, path, session, timeout=request_timeout)
                except requests.exceptions.Timeout:
                    return False, None, None, []
                except Exception:
                    return False, None, None, []
            
            # Use ThreadPoolExecutor for concurrent path checking
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                # Submit futures, but bail out early if exceeding timeout
                futures = []
                for path in SWAGGER_PATHS:
                    if (time.time() - start_time) >= (args.timeout * 0.9):
                        timed_out = True
                        break
                    futures.append(executor.submit(check_endpoint_with_timeout, path))
                
                # Process completed futures with strict timeout
                if futures:
                    remaining = (args.timeout * 0.85) - (time.time() - start_time)
                    if remaining > 0:
                        try:
                            for future in as_completed(futures, timeout=max(0.1, remaining)):
                                try:
                                    found, url, version, endpoints = future.result(timeout=0.3)
                                    if found:
                                        found_endpoints.append({
                                            "target": target,
                                            "endpoint": url,
                                            "version": version,
                                            "api_endpoints": endpoints
                                        })
                                except Exception:
                                    pass
                                
                                # Early exit if we've used up our time
                                if (time.time() - start_time) >= (args.timeout * 0.9):
                                    timed_out = True
                                    break
                        except TimeoutError:
                            timed_out = True
                
                # Cancel any remaining futures
                for future in futures:
                    future.cancel()
            
            scan_time = time.time() - start_time
            # Force status to timeout if we exceeded the limit
            if scan_time > args.timeout + 0.5:
                timed_out = True
            
            result = {
                "target": target,
                "scan_time": round(scan_time, 1),
                "endpoints": found_endpoints,
                "status": "timeout" if timed_out else "success"
            }
            completed_count[0] += 1
            active_targets.discard(target)
            if not args.json:
                progress = f"[{completed_count[0]}/{len(targets)}]"
                if timed_out:
                    print(f"{progress} ⏰ Timeout after {scan_time:.1f}s for {target}")
                elif found_endpoints:
                    print(f"{progress} ✅ Found {len(found_endpoints)} Swagger endpoint(s) in {scan_time:.1f}s for {target}")
                else:
                    print(f"{progress} ❌ No Swagger endpoints found in {scan_time:.1f}s for {target}")
            return result
            
        except TimeoutError:
            scan_time = time.time() - start_time
            result = {
                "target": target,
                "scan_time": round(scan_time, 1),
                "endpoints": [],
                "status": "timeout"
            }
            completed_count[0] += 1
            active_targets.discard(target)
            if not args.json:
                progress = f"[{completed_count[0]}/{len(targets)}]"
                print(f"{progress} ⏰ Timeout after {scan_time:.1f}s for {target}")
            return result
        except Exception as e:
            scan_time = time.time() - start_time
            result = {
                "target": target,
                "scan_time": round(scan_time, 1),
                "endpoints": [],
                "status": "error",
                "error": str(e)
            }
            completed_count[0] += 1
            active_targets.discard(target)
            if not args.json:
                progress = f"[{completed_count[0]}/{len(targets)}]"
                print(f"{progress} ❌ Error scanning {target}: {str(e)}")
            return result
        finally:
            session.close()  # Always close the session
    
    # Scan targets concurrently
    with ThreadPoolExecutor(max_workers=args.target_threads) as executor:
        futures = {executor.submit(scan_target_with_timeout, target): target for target in targets}
        
        for future in as_completed(futures):
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                # Handle any unexpected errors in the target scanning
                target = futures[future]
                completed_count[0] += 1
                active_targets.discard(target)
                result = {
                    "target": target,
                    "scan_time": 0,
                    "endpoints": [],
                    "status": "error",
                    "error": f"Unexpected error: {str(e)}"
                }
                all_results.append(result)
                if not args.json:
                    progress = f"[{completed_count[0]}/{len(targets)}]"
                    print(f"{progress} ❌ Unexpected error scanning {target}: {str(e)}")
    
    # Sort results by target for consistent output
    all_results.sort(key=lambda x: x["target"])
    
    total_scan_time = time.time() - total_start_time
    
    # Output results
    if args.json:
        # Collect all API endpoints with method, path, and full URL
        all_api_endpoints = []
        
        for result in all_results:
            for endpoint in result["endpoints"]:
                for api_ep in endpoint["api_endpoints"]:
                    all_api_endpoints.append({
                        "method": api_ep.get("method", ""),
                        "path": api_ep.get("endpoint", ""),
                        "full_url": api_ep.get("full_endpoint", "")
                    })
        
        # JSON output format - simplified with all endpoints
        json_output = {
            "scan_summary": {
                "total_targets": len(targets),
                "successful_scans": len([r for r in all_results if r["status"] == "success" and r["endpoints"]]),
                "timeout_targets": len([r for r in all_results if r["status"] == "timeout"]),
                "error_targets": len([r for r in all_results if r["status"] == "error"]),
                "total_endpoints_found": len(all_api_endpoints),
                "total_scan_time_seconds": round(total_scan_time, 1)
            },
            "endpoints": all_api_endpoints,
            "detailed_results": []
        }
        
        for result in all_results:
            target_result = {
                "target": result["target"],
                "status": result["status"],
                "scan_time_seconds": result["scan_time"],
                "swagger_endpoints": []
            }
            
            if result["status"] == "error":
                target_result["error"] = result.get("error", "")
            
            for endpoint in result["endpoints"]:
                swagger_ep = {
                    "url": endpoint["endpoint"],
                    "version": endpoint.get("version"),
                    "api_endpoints": []
                }
                
                # Add API endpoints with method and path
                for api_ep in endpoint["api_endpoints"]:
                    swagger_ep["api_endpoints"].append({
                        "method": api_ep.get("method", ""),
                        "path": api_ep.get("endpoint", ""),
                        "full_url": api_ep.get("full_endpoint", "")
                    })
                
                target_result["swagger_endpoints"].append(swagger_ep)
            
            json_output["detailed_results"].append(target_result)
        
        print(json.dumps(json_output, indent=2))
    else:
        # Text output (original format)
        print("\n" + "=" * 80)
        
        successful_scans = len([r for r in all_results if r["status"] == "success" and r["endpoints"]])
        timeout_targets = len([r for r in all_results if r["status"] == "timeout"])
        error_targets = len([r for r in all_results if r["status"] == "error"])
        total_endpoints = sum(len(r["endpoints"]) for r in all_results)
        
        if total_endpoints > 0:
            print(f"\n✅ Found {total_endpoints} Swagger endpoint(s) across {successful_scans} target(s) in {total_scan_time:.1f}s:")
            if timeout_targets > 0:
                print(f"⏰ {timeout_targets} target(s) timed out")
            if error_targets > 0:
                print(f"❌ {error_targets} target(s) had errors")
            print()
            
            for result in all_results:
                if result["endpoints"]:
                    print(f"🎯 Target: {result['target']} (scanned in {result['scan_time']}s)")
                    for idx, ep in enumerate(result["endpoints"], 1):
                        version_str = f" [v{ep['version']}]" if ep['version'] else ""
                        print(f"   [{idx}] {ep['endpoint']}{version_str}")
                        
                        # Display API endpoints if extracted
                        if ep['api_endpoints']:
                            print(f"       📡 Found {len(ep['api_endpoints'])} API endpoint(s):")
                            for api_ep in ep['api_endpoints'][:10]:  # Show first 10
                                method = api_ep.get('method', '')
                                path = api_ep.get('endpoint', '')
                                full_url = api_ep.get('full_endpoint', '')
                                print(f"          {method:6} {path}")
                            if len(ep['api_endpoints']) > 10:
                                print(f"          ... and {len(ep['api_endpoints']) - 10} more endpoints")
                    print()
        else:
            print(f"\n[!] No Swagger endpoints found across all targets in {total_scan_time:.1f}s.")
            if timeout_targets > 0:
                print(f"⏰ {timeout_targets} target(s) timed out")
            if error_targets > 0:
                print(f"❌ {error_targets} target(s) had errors")
        
        print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
