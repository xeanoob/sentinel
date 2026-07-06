"""API Parser — downloads and parses OpenAPI/Swagger specifications into CrawledPages."""

import httpx
from typing import Optional
from urllib.parse import urljoin, urlparse

from models import CrawledPage, FormData, FormField, ScanRequest

async def parse_openapi_schema(request: ScanRequest) -> list[CrawledPage]:
    """Fetch an OpenAPI schema and convert its endpoints into mock CrawledPages."""
    
    timeout = request.page_timeout_ms / 1000
    headers = request.custom_headers or {}
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers) as client:
        try:
            resp = await client.get(request.target_url, timeout=timeout)
            resp.raise_for_status()
            schema = resp.json()
        except Exception as e:
            # Return a single page with error if we can't parse the schema
            return [CrawledPage(url=request.target_url, depth=0, status_code=0, error=f"Failed to fetch/parse OpenAPI schema: {e}")]

    pages: list[CrawledPage] = []
    
    # Base URL extraction
    servers = schema.get("servers", [])
    base_url = servers[0].get("url", "") if servers else request.target_url
    if not base_url.startswith("http"):
        parsed_target = urlparse(request.target_url)
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}{base_url}"

    paths = schema.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() not in ["get", "post", "put", "patch", "delete"]:
                continue
                
            full_url = urljoin(base_url, path)
            
            # Extract parameters
            url_params = {}
            fields = []
            
            parameters = details.get("parameters", [])
            for param in parameters:
                param_name = param.get("name")
                if not param_name: continue
                
                param_in = param.get("in", "")
                if param_in == "query":
                    url_params[param_name] = ["API_FUZZ_TEST"]
                elif param_in in ["formData", "body"]:
                    fields.append(FormField(name=param_name, field_type="text", value="API_FUZZ_TEST"))
            
            # If there's a JSON body, we can simulate it as a form for our modules to inject
            request_body = details.get("requestBody", {})
            content = request_body.get("content", {})
            for content_type, schema_details in content.items():
                if content_type == "application/json":
                    properties = schema_details.get("schema", {}).get("properties", {})
                    for prop_name in properties.keys():
                        fields.append(FormField(name=prop_name, field_type="text", value="API_FUZZ_TEST"))

            forms = []
            if fields:
                forms.append(FormData(action=full_url, method=method.upper(), fields=fields))

            # If it's a GET request and has parameters, put them in url_params
            
            # Construct a CrawledPage
            page = CrawledPage(
                url=full_url,
                depth=0,
                status_code=200,
                headers={"Content-Type": "application/json"},
                body="",
                content_type="application/json",
                forms=forms,
                links=[],
                url_params=url_params
            )
            pages.append(page)

    return pages
