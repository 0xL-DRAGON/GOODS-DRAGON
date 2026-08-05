#!/usr/bin/env python3
"""Test all module imports - Fixed paths"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

errors = []
success = []

modules_to_test = [
    # core (inside modules/)
    ("core.logger", ["log_info", "log_error", "log_success", "log_warning"]),
    ("core.network", ["resolve_domain", "check_http_status"]),
    ("modules.core.updater", ["SelfUpdater"]),
    ("modules.core.payload_manager", ["PayloadManager"]),
    ("modules.core.stealth", ["StealthMode"]),
    ("modules.core.stealth_pro", ["StealthPro"]),
    ("modules.core.waf_bypass", ["WAFBypass"]),
    ("modules.core.browser_emulator", ["BrowserEmulator"]),
    ("modules.core.proxy_manager", ["ProxyManager"]),
    ("modules.core.ai_scanner", ["AIScanner"]),
    ("modules.core.http_client", []),
    ("modules.core.async_http", []),
    ("modules.core.user_agents", []),
    ("modules.core.waf_evasion", []),
    
    # recon
    ("modules.recon.subdomain", ["SubdomainFinder"]),
    ("modules.recon.wayback", ["WaybackScanner"]),
    ("modules.recon.active_scan", ["ActiveSubdomainScanner"]),
    ("modules.recon.takeover", ["SubdomainTakeover"]),
    ("modules.recon.cloud_enum", ["CloudEnum"]),
    ("modules.recon.cloud_scanner", ["CloudScanner"]),
    ("modules.recon.cloud_exploit", []),
    ("modules.recon.osint", ["OSINT"]),
    ("modules.recon.email_harvester", ["EmailHarvester"]),
    ("modules.recon.ad_enum", ["ADEnum"]),
    ("modules.recon.social_eng", ["SocialEngineering"]),
    ("modules.recon.threat_intel", ["ThreatIntel"]),
    ("modules.recon.dark_web", ["DarkWebMonitor"]),
    ("modules.recon.shodan", ["ShodanIntegration"]),
    ("modules.recon.censys", ["CensysIntegration"]),
    ("modules.recon.public_info", ["PublicInfo"]),
    ("modules.recon.phone_info", ["PhoneInfo"]),
    ("modules.recon.takeover_advanced", []),
    
    # web
    ("modules.web.disclosure", ["InfoDisclosureScanner"]),
    ("modules.web.sqli", ["SQLiScanner"]),
    ("modules.web.xss", ["XSSScanner"]),
    ("modules.web.login_bypass", ["LoginBypassScanner"]),
    ("modules.web.dir_bruteforce", ["DirBruteforce"]),
    ("modules.web.cms", ["CMSDetector"]),
    ("modules.web.cve_scan", ["CVEScanner"]),
    ("modules.web.js_deps", ["JSDependencyScanner"]),
    ("modules.web.tech_detect", ["TechnologyDetector"]),
    ("modules.web.headers_check", ["SecurityHeadersChecker"]),
    ("modules.web.git_scan", ["GitScanner"]),
    ("modules.web.waf_detect", ["WAFDetector"]),
    ("modules.web.idor", ["IDORScanner"]),
    ("modules.web.ssti", ["SSTIScanner"]),
    ("modules.web.ssrf", ["SSRFScanner"]),
    ("modules.web.lfi", ["LFIScanner"]),
    ("modules.web.cors", ["CORSChecker"]),
    ("modules.web.jwt", ["JWTScanner"]),
    ("modules.web.open_redirect", ["OpenRedirectScanner"]),
    ("modules.web.graphql", ["GraphQLScanner"]),
    ("modules.web.rate_limit", ["RateLimitChecker"]),
    ("modules.web.twofa_bypass", ["TwoFABypass"]),
    ("modules.web.param_discovery", ["ParameterDiscovery"]),
    ("modules.web.proxy", ["ProxyServer"]),
    ("modules.web.nikto_style", ["NiktoStyleScanner"]),
    ("modules.web.collaborator.blind_xss", ["BlindXSSCollaborator"]),
    ("modules.web.secret_scanner", ["SecretScanner"]),
    ("modules.web.version_scanner", ["VersionScanner"]),
    ("modules.web.broken_link", ["BrokenLinkChecker"]),
    ("modules.web.smart_fuzzing", ["SmartFuzzing"]),
    ("modules.web.business_logic", ["BusinessLogicChecker"]),
    ("modules.web.race_condition", ["RaceConditionDetector"]),
    ("modules.web.chained_attack", ["ChainedAttackScanner"]),
    ("modules.web.static_analysis", ["StaticAnalysis"]),
    ("modules.web.auto_throttle", ["AutoThrottle"]),
    ("modules.web.auto_advanced", ["AdvancedAuto"]),
    ("modules.web.auto_scanner", ["AutoScanner"]),
    ("modules.web.api_scanner", ["APIScanner"]),
    ("modules.web.rce_scanner", ["RCEScanner"]),
    ("modules.web.dir_traversal", ["DirTraversal"]),
    ("modules.web.api_key_scanner", ["APIKeyScanner"]),
    ("modules.web.jwt_oauth", ["JWTOAuthTester"]),
    ("modules.web.mobile_security", ["MobileSecurity"]),
    
    # scan
    ("modules.scan.portscan", ["PortScanner"]),
    ("modules.scan.s3", ["S3Finder"]),
    ("modules.scan.ssl_check", ["SSLChecker"]),
    ("modules.scan.host_discovery", ["HostDiscovery"]),
    ("modules.scan.bruteforce", ["BruteForce"]),
    ("modules.scan.password_crack", ["PasswordCracker"]),
    
    # exploit
    ("modules.exploit.exploit", ["ExploitModule"]),
    ("modules.exploit.dev", ["ExploitDev"]),
    
    # reporting
    ("modules.reporting.html_report", ["HTMLReport"]),
    ("modules.reporting.hackerone_format", ["HackerOneReport"]),
    ("modules.reporting.dynamic_report", ["DynamicReport"]),
    ("modules.reporting.advanced_report", ["AdvancedReport"]),
    
    # utils
    ("utils.helpers", []),
    
    # webui
    ("webui", ["app"]),
]

print("=" * 70)
print("🐉 GOODS-DRAGON - COMPLETE MODULE IMPORT TEST")
print("=" * 70)

for module_name, classes in modules_to_test:
    try:
        mod = __import__(module_name, fromlist=classes)
        if classes:
            for cls_name in classes:
                if hasattr(mod, cls_name):
                    print(f"  ✅ {module_name}.{cls_name}")
                    success.append(f"{module_name}.{cls_name}")
                else:
                    print(f"  ❌ {module_name}.{cls_name} - NOT FOUND")
                    errors.append(f"{module_name}.{cls_name} not found")
        else:
            print(f"  ✅ {module_name} (imported)")
            success.append(module_name)
    except Exception as e:
        print(f"  ❌ {module_name} - ERROR: {e}")
        errors.append(f"{module_name}: {str(e)}")

print("\n" + "=" * 70)
print(f"TOTAL MODULES TESTED: {len(success) + len(errors)}")
print(f"PASSED: {len(success)} ✅")
print(f"FAILED: {len(errors)} ❌")
print("=" * 70)

if errors:
    print("\n🔧 FAILED MODULES:")
    for err in errors:
        print(f"  ❌ {err}")
    print(f"\n💡 Run: pip install -r requirements.txt")
    sys.exit(1)
else:
    print("\n🎉 ALL MODULES LOADED SUCCESSFULLY!")
    print("🐉 GOODS-DRAGON is production-ready!")
    sys.exit(0)
