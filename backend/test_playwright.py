import asyncio
# pyrefly: ignore [missing-import]
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        print("Navigating to https://www.ambroise-boutrin.fr/ ...")
        await page.goto("https://www.ambroise-boutrin.fr/")
        print("Waiting 10 seconds for Vercel challenge to complete...")
        await page.wait_for_timeout(10000)
        content = await page.content()
        title = await page.title()
        print(f"Page title: {title}")
        
        # Extract links
        links = await page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")
        print(f"Found {len(links)} links.")
        if len(links) > 0:
            print(f"First 5 links: {links[:5]}")
            
        await browser.close()

asyncio.run(main())
