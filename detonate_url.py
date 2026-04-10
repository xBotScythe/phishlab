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
        browser = p.chromium.launch(args=[
            "--disable-features=SafeBrowsing",
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--window-size=1920,1080",
            "--disable-infobars",
            "--disable-notifications",
            "--lang=en-US",
        ])

        # derive UA from the actual chromium version playwright is running
        chrome_version = browser.version.split(".")[0]
        user_agent = (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
        )

        context = browser.new_context(
            record_har_path=f"{output_dir}/network_traffic.har",
            ignore_https_errors=True,
            user_agent=user_agent,
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="America/New_York",
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )

        # patch automation fingerprints before any page load
        context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', {
                get: () => [
                    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
                    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' },
                ]
            });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return 'Intel Inc.';
                if (parameter === 37446) return 'Intel Iris OpenGL Engine';
                return getParameter.call(this, parameter);
            };
            window.chrome = { runtime: {} };
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) =>
                parameters.name === 'notifications'
                    ? Promise.resolve({ state: Notification.permission })
                    : originalQuery(parameters);
        """)
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
            
            # js injection — dom iocs
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

            # js runtime analysis — captures things static html can't see
            print("running js runtime analysis...")
            js_runtime = page.evaluate("""() => {
                // kit signatures: globals that phishing kits commonly set
                const kitGlobals = Object.keys(window)
                    .filter(k => k.startsWith('__') || k.startsWith('_gt') || k.startsWith('_ph'))
                    .slice(0, 30);

                // localStorage (truncate values)
                const ls = {};
                try {
                    for (let i = 0; i < window.localStorage.length; i++) {
                        const k = window.localStorage.key(i);
                        ls[k] = (window.localStorage.getItem(k) || '').slice(0, 300);
                    }
                } catch(e) {}

                // sessionStorage
                const ss = {};
                try {
                    for (let i = 0; i < window.sessionStorage.length; i++) {
                        const k = window.sessionStorage.key(i);
                        ss[k] = (window.sessionStorage.getItem(k) || '').slice(0, 300);
                    }
                } catch(e) {}

                // inline script content (obfuscated kits often live here)
                const inlineScripts = Array.from(document.scripts)
                    .filter(s => !s.src && s.textContent.length > 50)
                    .map(s => s.textContent.slice(0, 500))
                    .slice(0, 5);

                return {
                    finalUrl:         window.location.href,
                    documentReferrer: document.referrer,
                    cookieNames:      document.cookie.split(';').map(c => c.split('=')[0].trim()).filter(Boolean),
                    kitGlobals:       kitGlobals,
                    localStorage:     ls,
                    sessionStorage:   ss,
                    inlineScripts:    inlineScripts,
                    pageLanguage:     document.documentElement.lang || '',
                }
            }""")
            with open(f"{output_dir}/js_runtime.json", "w", encoding="utf-8") as f:
                json.dump(js_runtime, f, indent=2)
            print("JS runtime analysis complete")

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
