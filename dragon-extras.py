#!/usr/bin/env python3
"""GOODS-DRAGON Extra Features — Run independently without touching main.py"""
import sys

if len(sys.argv) < 2:
    print("Usage: python3 dragon-extras.py [--dorks|--wp-enum|--takeover-advanced|--orchestrator] <target>")
    sys.exit(1)

cmd = sys.argv[1].replace("--", "")
target = sys.argv[2] if len(sys.argv) > 2 else None

if cmd == "dorks":
    if not target:
        print("❌ Target required. Example: python3 dragon-extras.py --dorks liara.ir")
        sys.exit(1)
    from modules.recon.dork_generator import DorkGenerator
    dorks = DorkGenerator(target).generate()
    print(f"\n🐉 Google Dorks for {target}:")
    print("=" * 50)
    for i, dork in enumerate(dorks, 1):
        print(f"[{i}] {dork}")
    print("=" * 50)

elif cmd == "wp-enum":
    if not target:
        print("❌ Target required. Example: python3 dragon-extras.py --wp-enum https://target.com")
        sys.exit(1)
    from modules.web.wp_enumerator import WPEnumerator
    wp = WPEnumerator(target, verbose=True)
    wp_results = wp.run()
    if wp_results:
        for plugin in wp_results:
            print(f"✅ Found: {plugin['plugin']} v{plugin['version']}")
    else:
        print("ℹ️  No WordPress plugins found.")

elif cmd == "takeover-advanced":
    if not target:
        print("❌ Target required. Example: python3 dragon-extras.py --takeover-advanced target.com")
        sys.exit(1)
    from modules.recon.subdomain_takeover_advanced import AdvancedSubdomainTakeover
    takeover = AdvancedSubdomainTakeover([target], verbose=True)
    results = takeover.run()
    if results:
        for t in results:
            print(f"🔥 Takeover possible: {t['subdomain']} -> {t['service']}")
    else:
        print("✅ No takeover vulnerabilities found.")

elif cmd == "orchestrator":
    if not target:
        print("❌ Target required. Example: python3 dragon-extras.py --orchestrator target.com")
        sys.exit(1)
    from modules.core.orchestrator import Orchestrator
    orch = Orchestrator(target, verbose=True)
    print(orch.run())
    sys.exit(0)

else:
    print(f"❌ Unknown command: {cmd}")
    print("Available: --dorks, --wp-enum, --takeover-advanced, --orchestrator")
