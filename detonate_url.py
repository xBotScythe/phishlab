import json
import os
import random
import string
import sys
from urllib.parse import urlparse, urlunparse, urlencode

from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth

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

        page = context.new_page()
        Stealth(
            navigator_languages_override=("en-US", "en"),
            navigator_platform_override="Win32",
            webgl_vendor_override="Intel Inc.",
            webgl_renderer_override="Intel Iris OpenGL Engine",
        ).apply_stealth_sync(page)

        try:
            page.goto(target_url, timeout=30000, wait_until="load")

            # cf phishing interstitial bypass
            try:
                selectors = [
                    'a:has-text("Ignore & Proceed")',
                    'a:has-text("Ignore")',
                    'text=Ignore & Proceed',
                    '[href*="proceed"]',
                ]
                clicked = False
                for sel in selectors:
                    el = page.locator(sel)
                    if el.count() > 0:
                        print("cloudflare phishing interstitial detected, bypassing...")
                        el.first.click()
                        clicked = True
                        break

                if not clicked:
                    clicked = page.evaluate("""() => {
                        const links = Array.from(document.querySelectorAll('a'));
                        const target = links.find(a => a.textContent.includes('Ignore'));
                        if (target) { target.click(); return true; }
                        return false;
                    }""")
                    if clicked:
                        print("cloudflare interstitial bypassed via js")

                if clicked:
                    page.wait_for_load_state("load", timeout=10000)
            except Exception:
                pass

            # wait for redirects to settle
            _prev_url = page.url
            for _ in range(6):
                try:
                    page.wait_for_load_state("networkidle", timeout=4000)
                    break
                except Exception:
                    pass
                _current_url = page.url
                if _current_url != _prev_url:
                    print(f"redirect detected: {_current_url}")
                    _prev_url = _current_url
                else:
                    break

            print(f"final url: {page.url}")

            # capture full page screenshot
            page.screenshot(path=f"{output_dir}/screenshot.png", full_page=True)
            print("screenshot saved")

            # dump html
            html_content = page.content()
            with open(f"{output_dir}/page_dom.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            print("html saved")
            
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

            print("running js runtime analysis...")
            js_runtime = page.evaluate("""() => {
                const kitGlobals = Object.keys(window)
                    .filter(k => k.startsWith('__') || k.startsWith('_gt') || k.startsWith('_ph'))
                    .slice(0, 30);

                const ls = {};
                try {
                    for (let i = 0; i < window.localStorage.length; i++) {
                        const k = window.localStorage.key(i);
                        ls[k] = (window.localStorage.getItem(k) || '').slice(0, 300);
                    }
                } catch(e) {}

                const ss = {};
                try {
                    for (let i = 0; i < window.sessionStorage.length; i++) {
                        const k = window.sessionStorage.key(i);
                        ss[k] = (window.sessionStorage.getItem(k) || '').slice(0, 300);
                    }
                } catch(e) {}

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

            # download capture
            downloads_dir = os.path.join(output_dir, "downloads")
            captured_downloads = []

            def _on_download(download):
                try:
                    os.makedirs(downloads_dir, exist_ok=True)
                    dest = os.path.join(downloads_dir, download.suggested_filename or "file")
                    download.save_as(dest)
                    captured_downloads.append({
                        "filename": download.suggested_filename,
                        "url": download.url,
                        "path": dest,
                    })
                    print(f"DOWNLOAD: captured {download.suggested_filename} from {download.url}")
                except Exception as e:
                    print(f"DOWNLOAD: save failed ({e})")

            page.on("download", _on_download)
            page.wait_for_timeout(2000)
            page.remove_listener("download", _on_download)

            if captured_downloads:
                with open(f"{output_dir}/downloads.json", "w", encoding="utf-8") as f:
                    json.dump(captured_downloads, f, indent=2)

            # form interaction
            try:
                rand_user = ''.join(random.choices(string.ascii_lowercase, k=8))
                rand_domain = ''.join(random.choices(string.ascii_lowercase, k=6))
                honeypot_email = f"{rand_user}@{rand_domain}.com"
                honeypot_pass = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$", k=14))

                form_result = page.evaluate("""([honeypotEmail, honeypotPass]) => {
                    const forms = Array.from(document.forms);
                    const candidates = forms.filter(f => {
                        const inputs = Array.from(f.querySelectorAll('input'));
                        return inputs.some(i => i.type === 'password');
                    });

                    if (candidates.length === 0) return null;

                    const form = candidates[0];
                    const inputs = Array.from(form.querySelectorAll('input'));
                    const filled = {};

                    for (const input of inputs) {
                        if (input.type === 'hidden' || input.type === 'submit' || input.type === 'button') continue;
                        if (input.type === 'email' || input.name.match(/email|user|login|account/i) || input.type === 'text') {
                            input.value = honeypotEmail;
                            input.dispatchEvent(new Event('input', { bubbles: true }));
                            input.dispatchEvent(new Event('change', { bubbles: true }));
                            filled[input.name || input.type] = honeypotEmail;
                        } else if (input.type === 'password') {
                            input.value = honeypotPass;
                            input.dispatchEvent(new Event('input', { bubbles: true }));
                            input.dispatchEvent(new Event('change', { bubbles: true }));
                            filled[input.name || 'password'] = '***';
                        }
                    }

                    return {
                        action: form.action || window.location.href,
                        method: (form.method || 'GET').toUpperCase(),
                        fields_filled: filled,
                        input_count: inputs.filter(i => i.type !== 'hidden').length,
                    };
                }""", [honeypot_email, honeypot_pass])

                if form_result:
                    print(f"FORM: found credential form, action={form_result['action']} method={form_result['method']}")

                    submission_capture = {"request": None}
                    form_action = form_result["action"]

                    def capture_request(request):
                        # ignore static assets — only care about the form submission itself
                        if request.resource_type not in ("document", "xhr", "fetch"):
                            return
                        if submission_capture["request"] is not None:
                            return
                        submission_capture["request"] = {
                            "url": request.url,
                            "method": request.method,
                            "post_data": request.post_data[:2000] if request.post_data else None,
                        }

                    page.on("request", capture_request)

                    try:
                        if form_result["method"] == "GET":
                            # GET forms encode credentials into the URL — navigate and capture
                            params = {k: (honeypot_pass if v == "***" else v) for k, v in form_result["fields_filled"].items()}
                            qs = urlencode(params)
                            parsed = urlparse(form_action)
                            existing_qs = parsed.query
                            submit_url = urlunparse(parsed._replace(query=(existing_qs + "&" + qs) if existing_qs else qs))
                            page.goto(submit_url, wait_until="load", timeout=8000)
                            # synthesize the submission record from what we built
                            if not submission_capture["request"]:
                                submission_capture["request"] = {
                                    "url": submit_url,
                                    "method": "GET",
                                    "post_data": None,
                                }
                        else:
                            page.evaluate("document.forms[0].requestSubmit ? document.forms[0].requestSubmit() : document.forms[0].submit()")
                            try:
                                page.wait_for_load_state("networkidle", timeout=5000)
                            except Exception:
                                page.wait_for_timeout(2000)
                    except Exception:
                        pass

                    page.remove_listener("request", capture_request)

                    form_data = {
                        "form_action": form_action,
                        "form_method": form_result["method"],
                        "fields_filled": form_result["fields_filled"],
                        "input_count": form_result["input_count"],
                        "submission": submission_capture["request"],
                        "post_submit_url": page.url,
                    }

                    with open(f"{output_dir}/form_submission.json", "w", encoding="utf-8") as f:
                        json.dump(form_data, f, indent=2)
                    print(f"FORM: submission -> {submission_capture['request']['url'] if submission_capture['request'] else 'no request captured'}")
            except Exception as e:
                print(f"FORM: interaction failed ({e})")

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
