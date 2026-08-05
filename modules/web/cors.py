#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import random
import urllib.parse
from typing import List, Dict, Optional, Tuple
from modules.core.http_client import HTTPClient
from modules.core.payload_manager import PayloadManager
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class CORSChecker:
    """
    Advanced CORS (Cross-Origin Resource Sharing) Misconfiguration Scanner
    Supports: Origin Reflection, Null Origin, Wildcard Origin, Trusted Origins,
              Preflight Checks, Credentialed Requests, Internal IP Exposure
    Combined Power: Internal Payloads (150+) + Payload Manager Integration
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target.rstrip('/')
        self.verbose = verbose
        self.client = HTTPClient(timeout=30, retries=5, verbose=verbose)
        self.payload_manager = PayloadManager(verbose=verbose)
        self.results = []
        self.payloads_tested = 0

        # ---------- TRUSTED ORIGINS (FOR MANIPULATION) ----------
        self.trusted_origins = [
            "example.com", "test.com", "demo.com", "dev.com", "staging.com",
            "prod.com", "admin.com", "api.com", "app.com", "web.com",
            "mobile.com", "cdn.com", "static.com", "assets.com", "media.com",
            "images.com", "videos.com", "docs.com", "files.com", "uploads.com",
            "download.com", "backup.com", "mirror.com", "proxy.com", "gateway.com",
            "auth.com", "login.com", "signup.com", "register.com", "profile.com",
            "dashboard.com", "portal.com", "support.com", "help.com", "contact.com",
            "about.com", "blog.com", "news.com", "forum.com", "community.com",
            "shop.com", "store.com", "cart.com", "checkout.com", "payment.com",
            "order.com", "track.com", "ship.com", "deliver.com", "review.com",
            "rating.com", "comment.com", "share.com", "like.com", "follow.com",
            "message.com", "chat.com", "call.com", "video.com", "audio.com",
            "file.com", "folder.com", "drive.com", "cloud.com", "sync.com",
            "backup.com", "restore.com", "export.com", "import.com", "print.com",
            "pdf.com", "doc.com", "sheet.com", "slide.com", "form.com",
            "survey.com", "poll.com", "quiz.com", "game.com", "play.com",
            "watch.com", "listen.com", "read.com", "write.com", "draw.com",
            "paint.com", "code.com", "develop.com", "build.com", "test.com",
            "deploy.com", "monitor.com", "log.com", "metric.com", "alert.com",
            "report.com", "analytics.com", "insight.com", "intel.com", "secure.com",
            "safe.com", "privacy.com", "policy.com", "terms.com", "legal.com",
            "copyright.com", "trademark.com", "patent.com", "license.com",
            "opensource.com", "community.com", "education.com", "research.com",
            "science.com", "tech.com", "health.com", "fitness.com", "sport.com",
            "travel.com", "food.com", "drink.com", "music.com", "art.com",
            "photo.com", "video.com", "movie.com", "tv.com", "radio.com",
            "podcast.com", "stream.com", "live.com", "event.com", "ticket.com",
            "booking.com", "reserve.com", "schedule.com", "calendar.com", "date.com",
            "time.com", "clock.com", "alarm.com", "timer.com", "stopwatch.com",
            "counter.com", "score.com", "leaderboard.com", "rank.com", "level.com",
            "badge.com", "achievement.com", "reward.com", "point.com", "coin.com",
            "token.com", "credit.com", "debit.com", "wallet.com", "balance.com",
            "transaction.com", "transfer.com", "withdraw.com", "deposit.com",
            "payment.com", "invoice.com", "receipt.com", "bill.com", "tax.com",
            "fee.com", "price.com", "cost.com", "value.com", "worth.com",
            "estimate.com", "quote.com", "offer.com", "discount.com", "coupon.com",
            "voucher.com", "gift.com", "card.com", "membership.com", "subscription.com",
            "plan.com", "package.com", "bundle.com", "deal.com", "sale.com",
            "clearance.com", "outlet.com", "warehouse.com", "inventory.com", "stock.com",
            "supply.com", "chain.com", "logistics.com", "shipping.com", "delivery.com",
            "courier.com", "post.com", "mail.com", "email.com", "inbox.com",
            "outbox.com", "draft.com", "sent.com", "spam.com", "trash.com",
            "archive.com", "folder.com", "label.com", "tag.com", "category.com",
            "group.com", "team.com", "staff.com", "employee.com", "manager.com",
            "director.com", "ceo.com", "founder.com", "partner.com", "client.com",
            "customer.com", "vendor.com", "supplier.com", "distributor.com", "retailer.com",
            "wholesaler.com", "manufacturer.com", "producer.com", "creator.com", "designer.com",
            "developer.com", "engineer.com", "analyst.com", "consultant.com", "advisor.com",
            "expert.com", "specialist.com", "technician.com", "operator.com", "agent.com",
            "representative.com", "ambassador.com", "advocate.com", "champion.com", "leader.com",
            "mentor.com", "coach.com", "trainer.com", "instructor.com", "teacher.com",
            "professor.com", "doctor.com", "nurse.com", "therapist.com", "counselor.com",
            "socialworker.com", "psychologist.com", "psychiatrist.com", "dentist.com", "veterinarian.com",
            "pharmacist.com", "physician.com", "surgeon.com", "radiologist.com", "pathologist.com",
            "anesthesiologist.com", "neurologist.com", "cardiologist.com", "oncologist.com", "pediatrician.com",
            "obstetrician.com", "gynecologist.com", "dermatologist.com", "ophthalmologist.com", "otolaryngologist.com",
            "urologist.com", "nephrologist.com", "endocrinologist.com", "rheumatologist.com", "allergist.com",
            "immunologist.com", "infectiousdisease.com", "pulmonologist.com", "gastroenterologist.com", "hepatologist.com",
            "hematologist.com", "orthopedist.com", "neurosurgeon.com", "plasticsurgeon.com", "thoracicsurgeon.com",
            "vascularsurgeon.com", "cardiacsurgeon.com", "transplantsurgeon.com", "pediatricsurgeon.com", "orthopedicsurgeon.com",
            "urologicsurgeon.com", "gynecologicsurgeon.com", "obstetricsurgeon.com", "dentalsurgeon.com", "oralsurgeon.com",
            "maxillofacialsurgeon.com", "oculoplasticsurgeon.com", "refractivesurgeon.com", "lasiksurgeon.com", "cataractsurgeon.com",
            "retinasurgeon.com", "glaucomasurgeon.com", "corneasurgeon.com", "keratoconussurgeon.com", "pterygiumsurgery.com",
            "strabismussurgery.com", "vitrectomysurgery.com", "trabeculectomysurgery.com", "cataractsurgery.com", "lasiksurgery.com",
            "refractivesurgery.com", "oculoplasticsurgery.com", "orbitaldecompressionsurgery.com", "blepharoplastysurgery.com",
            "ptosissurgery.com", "entropionsurgery.com", "ectropionsurgery.com", "dacryocystorhinostomysurgery.com",
            "orbitalfracturesurgery.com", "enucleationsurgery.com", "eviscerationsurgery.com", "keratoprosthesissurgery.com",
            "corneatransplantsurgery.com", "conjunctivoplasty.com", "pterygiumexcision.com", "limbalstemcelltransplant.com",
            "amnioticmembranetransplant.com", "cornealcrosslinking.com", "intracornealringsegment.com",
            "photorefractivekeratectomy.com", "laserassistedinsitukeratomileusis.com", "smallincisionlenticuleextraction.com",
            "refractivelensexchange.com", "intraocularlensimplant.com", "phacoemulsification.com",
            "extracapsularcataractextraction.com", "intracapsularcataractextraction.com"
        ]

        # ---------- INTERNAL PAYLOADS (150+ FOR SPEED & INDEPENDENCE) ----------
        self.internal_payloads = self._load_internal_payloads()

        # ---------- PAYLOAD MANAGER PAYLOADS (FOR UPDATES) ----------
        self.manager_payloads = self._load_manager_payloads()

        # ---------- COMBINED PAYLOADS ----------
        self.all_payloads = list(set(self.internal_payloads + self.manager_payloads))

        # ---------- SUCCESS INDICATORS ----------
        self.success_indicators = [
            "access-control-allow-origin",
            "Access-Control-Allow-Origin",
            "access-control-allow-credentials",
            "Access-Control-Allow-Credentials",
            "access-control-allow-methods",
            "Access-Control-Allow-Methods",
            "access-control-allow-headers",
            "Access-Control-Allow-Headers",
            "access-control-expose-headers",
            "Access-Control-Expose-Headers",
            "access-control-max-age",
            "Access-Control-Max-Age",
            "origin",
            "Origin",
            "null",
            "*",
            "wildcard",
            "credentials",
            "Credential",
            "xhr",
            "fetch",
            "XMLHttpRequest",
            "preflight",
            "OPTIONS"
        ]

    def _load_internal_payloads(self) -> List[str]:
        """Internal payloads (150+ for speed and independence)"""
        payloads = []

        # ----- ORIGIN HEADER VALUES -----
        origins = [
            "https://evil.com",
            "https://attacker.com",
            "https://malicious.com",
            "https://phishing.com",
            "https://hacker.com",
            "https://cracker.com",
            "https://breacher.com",
            "https://exploiter.com",
            "https://injector.com",
            "https://scanner.com",
            "https://fuzzer.com",
            "https://pentester.com",
            "https://security.com",
            "https://vulnerable.com",
            "https://exploit.com",
            "https://payload.com",
            "https://shell.com",
            "https://backdoor.com",
            "https://trojan.com",
            "https://virus.com",
            "https://malware.com",
            "https://ransomware.com",
            "https://spyware.com",
            "https://adware.com",
            "https://keylogger.com",
            "https://rootkit.com",
            "https://worm.com",
            "https://botnet.com",
            "https://zombie.com",
            "https://ddos.com",
            "https://pharming.com",
            "https://spoofing.com",
            "https://sniffing.com",
            "https://spoof.com",
            "https://fake.com",
            "https://fraud.com",
            "https://scam.com",
            "https://hoax.com",
            "https://fake.com",
            "https://dummy.com",
            "https://test.com",
            "https://demo.com",
            "https://example.com",
            "https://localhost",
            "https://127.0.0.1",
            "https://192.168.1.1",
            "https://10.0.0.1",
            "https://172.16.0.1",
            "https://0.0.0.0",
            "https://::1",
            "https://localhost:8080",
            "https://localhost:8443",
            "https://localhost:3000",
            "https://localhost:5000",
            "https://localhost:8000",
            "https://127.0.0.1:8080",
            "https://127.0.0.1:8443",
            "https://127.0.0.1:3000",
            "https://127.0.0.1:5000",
            "https://127.0.0.1:8000",
        ]
        payloads.extend(origins)

        # ----- PROTOCOL-RELATIVE ORIGINS -----
        protocol_relative = [
            "//evil.com",
            "//attacker.com",
            "//malicious.com",
            "//phishing.com",
            "//hacker.com",
            "//cracker.com",
            "//breacher.com",
            "//exploiter.com",
            "//injector.com",
            "//scanner.com",
            "//fuzzer.com",
            "//pentester.com",
            "//security.com",
            "//vulnerable.com",
            "//exploit.com",
            "//payload.com",
            "//shell.com",
            "//backdoor.com",
            "//trojan.com",
            "//virus.com",
            "//malware.com",
            "//ransomware.com",
            "//spyware.com",
            "//adware.com",
            "//keylogger.com",
            "//rootkit.com",
            "//worm.com",
            "//botnet.com",
            "//zombie.com",
            "//ddos.com",
            "//pharming.com",
            "//spoofing.com",
            "//sniffing.com",
            "//spoof.com",
            "//fake.com",
            "//fraud.com",
            "//scam.com",
            "//hoax.com",
            "//fake.com",
            "//dummy.com",
            "//test.com",
            "//demo.com",
            "//example.com",
            "//localhost",
            "//127.0.0.1",
        ]
        payloads.extend(protocol_relative)

        # ----- NULL ORIGIN -----
        null_origins = [
            "null",
            "NULL",
            "Null",
            "nUlL",
            "NuLl",
            "nULl",
            "NulL",
            "nulL",
            "NULl",
            "NulL",
            "nUlL",
            "NuLL",
            "NULL ",
            " null",
            "null ",
            " null ",
            "null%00",
            "null%0a",
            "null%0d",
            "null%20",
            "null%09",
        ]
        payloads.extend(null_origins)

        # ----- ENCODED ORIGINS -----
        encoded_origins = [
            "https://evil.com%00",
            "https://evil.com%0a",
            "https://evil.com%0d",
            "https://evil.com%20",
            "https://evil.com%09",
            "https://evil.com%2f",
            "https://evil.com%2e",
            "https://evil.com%2e%2e",
            "https://evil.com%2f%2e%2e",
            "https://evil.com%2f%2e%2e%2f",
            "https://evil.com%2f..",
            "https://evil.com%2f..%2f",
            "https://evil.com%2f..%2f..",
            "https://evil.com%2f..%2f..%2f",
            "https://evil.com%2f..%2f..%2f..",
        ]
        payloads.extend(encoded_origins)

        # ----- OBFUSCATED ORIGINS -----
        obfuscated_origins = [
            "https://evil.com@legitimate.com",
            "https://evil.com%2e%2e%2flegitimate.com",
            "https://evil.com%2f%2flegitimate.com",
            "https://evil.com%3f@legitimate.com",
            "https://evil.com%23@legitimate.com",
            "https://evil.com#@legitimate.com",
            "https://evil.com?@legitimate.com",
            "https://evil.com/../legitimate.com",
            "https://evil.com%2e%2e%2flegitimate.com",
            "https://evil.com%2f%2e%2e%2flegitimate.com",
            "https://evil.com%2f%2e%2e%2flegitimate.com%2f",
            "https://evil.com%2f..%2flegitimate.com",
            "https://evil.com%2f..%2f..%2flegitimate.com",
        ]
        payloads.extend(obfuscated_origins)

        # ----- SCHEME VARIATIONS -----
        scheme_variations = [
            "http://evil.com",
            "http://evil.com:80",
            "http://evil.com:8080",
            "http://evil.com:443",
            "http://evil.com:8443",
            "http://evil.com:3000",
            "http://evil.com:5000",
            "http://evil.com:8000",
            "ftp://evil.com",
            "ftp://evil.com:21",
            "sftp://evil.com",
            "sftp://evil.com:22",
            "ssh://evil.com",
            "ssh://evil.com:22",
            "telnet://evil.com",
            "telnet://evil.com:23",
            "gopher://evil.com",
            "gopher://evil.com:70",
            "dict://evil.com",
            "dict://evil.com:2628",
            "file:///etc/passwd",
            "file:///C:/windows/win.ini",
            "file:///dev/null",
            "file:///dev/zero",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///var/log/apache2/access.log",
            "file:///var/log/apache2/error.log",
            "file:///var/log/nginx/access.log",
            "file:///var/log/nginx/error.log",
        ]
        payloads.extend(scheme_variations)

        # ----- TRUSTED ORIGINS MANIPULATION -----
        for origin in self.trusted_origins[:50]:
            manipulated = [
                f"https://evil.com.{origin}",
                f"https://evil.com-{origin}",
                f"https://evil.com_{origin}",
                f"https://evil.com+{origin}",
                f"https://evil.com%2e{origin}",
                f"https://evil.com%2d{origin}",
                f"https://evil.com%5f{origin}",
                f"https://evil.com%2b{origin}",
                f"https://evil.com%2e%2e{origin}",
                f"https://evil.com..{origin}",
                f"https://evil.com-{origin}.com",
                f"https://evil.com.{origin}.com",
            ]
            payloads.extend(manipulated)

        return list(set(payloads))

    def _load_manager_payloads(self) -> List[str]:
        """Load payloads from Payload Manager"""
        payloads = []
        tags = ["origin", "null", "encoded", "obfuscated", "scheme", "trusted"]
        for tag in tags:
            results = self.payload_manager.get_payloads("cors", tags=[tag], limit=50)
            for p in results:
                if 'value' in p:
                    payloads.append(p['value'])
        return list(set(payloads))

    def test_cors(self, origin: str) -> bool:
        """Test a single CORS origin"""
        headers = {"Origin": origin}
        resp = self.client.get(self.target, headers=headers)
        if not resp:
            return False

        self.payloads_tested += 1

        # Check for CORS headers
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')
        acam = resp.headers.get('Access-Control-Allow-Methods', '')
        acah = resp.headers.get('Access-Control-Allow-Headers', '')
        aceh = resp.headers.get('Access-Control-Expose-Headers', '')
        acma = resp.headers.get('Access-Control-Max-Age', '')

        if acao:
            result = {
                "origin": origin,
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": acac,
                "access_control_allow_methods": acam,
                "access_control_allow_headers": acah,
                "access_control_expose_headers": aceh,
                "access_control_max_age": acma,
                "status": resp.status_code,
                "vulnerable": self._is_vulnerable(acao, acac, origin)
            }
            self.results.append(result)

            if result["vulnerable"]:
                log_success(f"CORS vulnerability found! Origin: {origin} -> ACAO: {acao}")
            elif self.verbose:
                log_debug(f"CORS header found for origin: {origin} -> ACAO: {acao}")

            return True

        return False

    def _is_vulnerable(self, acao: str, acac: str, origin: str) -> bool:
        """Determine if CORS configuration is vulnerable"""
        # Wildcard with credentials
        if acao == "*" and acac.lower() == "true":
            return True

        # Null origin
        if origin.lower() == "null" and (acao == "null" or acao == origin):
            return True

        # Reflected origin (origin echoed back)
        if acao == origin:
            return True

        # Trusted origin manipulation
        for trusted in self.trusted_origins:
            if trusted in origin and acao == origin:
                return True

        return False

    def test_preflight(self) -> bool:
        """Test CORS preflight (OPTIONS request)"""
        headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Requested-With"
        }
        resp = self.client.request("OPTIONS", self.target, headers=headers)
        if not resp:
            return False

        acam = resp.headers.get('Access-Control-Allow-Methods', '')
        acah = resp.headers.get('Access-Control-Allow-Headers', '')
        acao = resp.headers.get('Access-Control-Allow-Origin', '')

        if acam or acah or acao:
            result = {
                "type": "preflight",
                "origin": "https://evil.com",
                "access_control_allow_methods": acam,
                "access_control_allow_headers": acah,
                "access_control_allow_origin": acao,
                "status": resp.status_code,
                "vulnerable": acao == "https://evil.com" or acao == "*"
            }
            self.results.append(result)
            if result["vulnerable"]:
                log_success(f"Preflight vulnerability found! ACAO: {acao}")
            return True

        return False

    def run(self) -> Dict:
        log_info(f"Starting CORS check on: {self.target}")
        log_info(f"Testing {len(self.all_payloads)} origins (Internal: {len(self.internal_payloads)} + Manager: {len(self.manager_payloads)})")

        # Test standard origins
        shuffled = self.all_payloads.copy()
        random.shuffle(shuffled)
        for origin in shuffled[:150]:  # Limit to 150 for speed
            self.test_cors(origin)

        # Test preflight
        self.test_preflight()

        # Summary
        vulnerable = [r for r in self.results if r.get("vulnerable", False)]
        log_success(f"CORS check completed. Found {len(vulnerable)} vulnerabilities.")
        return {
            "target": self.target,
            "scan_type": "cors",
            "total_payloads_tested": min(len(self.all_payloads), 150) + 1,
            "payloads_internal": len(self.internal_payloads),
            "payloads_manager": len(self.manager_payloads),
            "vulnerable_count": len(vulnerable),
            "results": self.results
        }
