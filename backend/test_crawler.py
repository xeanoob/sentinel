import asyncio
from scanner.crawler import crawl
from models import ScanRequest
import sys

async def main():
    req = ScanRequest(target_url=sys.argv[1], max_depth=3, max_concurrency=5, same_domain_only=True)
    ev = asyncio.Event()
    async def on_page(page):
        print(f"Found page: {page.url}")
        print(f"Links found: {page.links}")
    pages = await crawl(req, on_page, ev)
    print(f"Total pages: {len(pages)}")

asyncio.run(main())
