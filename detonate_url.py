import json
import os
import sys
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

def detonate(target_url, output_dir="/cage_drop"):
    parsed = urlparse(target_url)
    if parsed.scheme not in ["http", "https"]:
        raise ValueError(f"Invalid protocol '{parsed.scheme}'. Only HTTP/HTTPS allowed.")

    print(f"analyzing: {target_url}")

    # prepare output
    os.makedirs(output_dir, exist_ok=True)

    with sync_playwright() as p:
        # launch browser (evasion args)
        browser = p.chromium.launch(args=[
            "--disable-features=SafeBrowsing", # Prevent Google's red warning screen
            "--disable-blink-features=AutomationControlled" # Soft anti-bot bypass
        ])
        
        # setup context (har/ua)
        context = browser.new_context(
            record_har_path=f"{output_dir}/network_traffic.har",
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        )
        page = context.new_page()

        try:
            # load target
            page.goto(target_url, timeout=30000, wait_until="domcontentloaded")
            
            # wait for cf
            page.wait_for_timeout(3000)

            # cf interstitial bypass
            try:
                # soft locate proceed
                proceed_btn = page.get_by_role("button", name="Ignore & Proceed")
                if proceed_btn.count() > 0:
                    print("Found Cloudflare Phishing Interstitial. Bypassing...")
                    proceed_btn.first.click()
                    # Wait for the actual payload to load after clicking proceed
                    page.wait_for_timeout(5000)
            except Exception as e:
                pass

            # wait 5 extra seconds to allow any delayed JS redirects
            page.wait_for_timeout(5000)

            # capture full page screenshot
            page.screenshot(path=f"{output_dir}/screenshot.png", full_page=True)
            print("screenshot saved")

            # dump html
            html_content = page.content()
            with open(f"{output_dir}/page_dom.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            print("html saved")
            
            # js injection extraction
            print("extracting DOM structures via JS injection...")
            js_iocs = page.evaluate("""() => {
                return {
                    scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean),
                    iframes: Array.from(document.querySelectorAll('iframe')).map(i => i.src).filter(Boolean),
                    forms:   Array.from(document.forms).map(f => f.action).filter(Boolean),
                    links:   Array.from(document.links).map(l => l.href).filter(Boolean),
                    title:   document.title,
                    h1s:     Array.from(document.querySelectorAll('h1')).map(h => h.innerText).filter(Boolean),
                    metaDesc: document.querySelector('meta[name="description"]')?.content || ""
                }
            }""")
            
            with open(f"{output_dir}/extracted_iocs.json", "w", encoding="utf-8") as f:
                json.dump(js_iocs, f, indent=2)
            print("DOM iocs extracted")

        except Exception as e:
            print(f"error: {str(e)}")
            with open(f"{output_dir}/error.log", "w") as f:
                f.write(str(e))
        
        finally:
            # finalize har
            context.close()
            browser.close()
            print("analysis complete")

if __name__ == "__main__":
    # get target from env
    url_to_analyze = os.environ.get("TARGET_URL")
    
    if not url_to_analyze:
        print("error: target_url not set")
        sys.exit(1)

    detonate(url_to_analyze)
