#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import json
import os
import requests
from core.logger import log_info, log_success, log_warning, log_error, log_debug

class PhoneInfo:
    def __init__(self, phone_number, verbose=False):
        self.phone = self.clean_number(phone_number)
        self.verbose = verbose
        self.results = {}
        
        # دیتابیس کامل اپراتورهای ایران
        self.iran_operators = {
            # همراه اول (MCI)
            '0910': 'Hamrahe Aval (MCI)',
            '0911': 'Hamrahe Aval (MCI)',
            '0912': 'Hamrahe Aval (MCI)',
            '0913': 'Hamrahe Aval (MCI)',
            '0914': 'Hamrahe Aval (MCI)',
            '0915': 'Hamrahe Aval (MCI)',
            '0916': 'Hamrahe Aval (MCI)',
            '0917': 'Hamrahe Aval (MCI)',
            '0918': 'Hamrahe Aval (MCI)',
            '0919': 'Hamrahe Aval (MCI)',
            # ایرانسل
            '0901': 'Irancell',
            '0902': 'Irancell',
            '0903': 'Irancell',
            '0904': 'Irancell',
            '0905': 'Irancell',
            '0906': 'Irancell',
            '0907': 'Irancell',
            '0908': 'Irancell',
            '0909': 'Irancell',
            '0930': 'Irancell',
            '0933': 'Irancell',
            '0935': 'Irancell',
            '0936': 'Irancell',
            '0937': 'Irancell',
            '0938': 'Irancell',
            '0939': 'Irancell',
            '0940': 'Irancell',
            '0941': 'Irancell',
            '0942': 'Irancell',
            # رایتل
            '0920': 'Rightel',
            '0921': 'Rightel',
            '0922': 'Rightel',
            '0923': 'Rightel',
            '0924': 'Rightel',
            # شاتل موبایل
            '0990': 'Shatel Mobile',
            '0991': 'Shatel Mobile',
            '0992': 'Shatel Mobile',
            '0993': 'Shatel Mobile',
            '0994': 'Shatel Mobile',
            # آپادانا
            '0995': 'Apadana',
            '0996': 'Apadana',
            # سامان
            '0998': 'Saman',
            '0999': 'Saman',
            # تالیا
            '0997': 'Taliya',
        }
        
        # پیش‌شماره‌های استان‌ها (برای خطوط ثابت)
        self.area_codes = {
            '021': 'Tehran',
            '023': 'Semnan',
            '024': 'Zanjan',
            '025': 'Qom',
            '026': 'Alborz',
            '028': 'Qazvin',
            '031': 'Isfahan',
            '034': 'Kerman',
            '035': 'Yazd',
            '036': 'Mazandaran',
            '041': 'Tabriz',
            '044': 'Urmia',
            '045': 'Ardebil',
            '051': 'Mashhad',
            '054': 'Zahedan',
            '056': 'Bandar Abbas',
            '058': 'Gorgan',
            '061': 'Ahvaz',
            '066': 'Khorramabad',
            '071': 'Shiraz',
            '074': 'Yasuj',
            '076': 'Bushehr',
            '077': 'Kish',
            '081': 'Hamadan',
            '083': 'Kermanshah',
            '084': 'Ilam',
            '086': 'Arak',
            '087': 'Sanandaj',
            '088': 'Yasuj'
        }
        
        # پیش‌شماره‌های بین‌المللی
        self.country_codes = {
            '98': 'Iran',
            '1': 'USA/Canada',
            '44': 'United Kingdom',
            '91': 'India',
            '86': 'China',
            '81': 'Japan',
            '82': 'South Korea',
            '49': 'Germany',
            '33': 'France',
            '39': 'Italy',
            '34': 'Spain',
            '61': 'Australia',
            '7': 'Russia',
            '55': 'Brazil',
            '52': 'Mexico',
            '90': 'Turkey',
            '92': 'Pakistan',
            '20': 'Egypt',
            '27': 'South Africa',
            '31': 'Netherlands',
            '41': 'Switzerland',
            '46': 'Sweden',
            '47': 'Norway',
            '45': 'Denmark',
            '48': 'Poland',
            '351': 'Portugal',
            '353': 'Ireland',
            '971': 'UAE',
            '966': 'Saudi Arabia',
            '964': 'Iraq',
            '963': 'Syria',
            '962': 'Jordan',
            '961': 'Lebanon',
            '972': 'Israel',
            '30': 'Greece',
            '36': 'Hungary',
            '420': 'Czech Republic',
            '43': 'Austria',
            '32': 'Belgium'
        }

    def clean_number(self, num):
        """پاکسازی شماره و تبدیل به فرمت استاندارد"""
        num = re.sub(r'[^0-9+]', '', str(num))
        # اگر با 0 شروع شد، 0 رو حذف کن و 98 رو اضافه کن
        if num.startswith('0'):
            num = '98' + num[1:]
        # اگر با + شروع شد، + رو حذف کن
        elif num.startswith('+'):
            num = num[1:]
        return num

    def detect_country(self):
        """تشخیص کشور از پیش‌شماره"""
        for code, country in self.country_codes.items():
            if self.phone.startswith(code):
                self.results['country'] = country
                self.results['country_code'] = code
                return code
        self.results['country'] = 'Unknown'
        self.results['country_code'] = 'Unknown'
        return None

    def detect_operator_iran(self):
        """تشخیص اپراتور برای شماره‌های ایران"""
        if self.results.get('country_code') == '98' and len(self.phone) >= 10:
            # برای شماره‌های همراه، پیش‌شماره 4 رقمی بعد از 98
            if len(self.phone) == 11 or len(self.phone) == 10:
                prefix = self.phone[2:6] if len(self.phone) >= 6 else None
                if prefix and prefix in self.iran_operators:
                    self.results['operator'] = self.iran_operators[prefix]
                    return self.results['operator']
        return None

    def get_phone_type(self):
        """تشخیص نوع شماره (همراه، ثابت، خط ویژه)"""
        if self.results.get('country_code') == '98':
            # شماره‌های همراه معمولاً با 9 شروع می‌شوند بعد از کد کشور
            if len(self.phone) == 11 and self.phone.startswith('989'):
                self.results['type'] = 'Mobile'
            elif len(self.phone) == 10 and self.phone.startswith('9'):
                self.results['type'] = 'Mobile'
            elif len(self.phone) >= 10 and self.phone[2:5] in self.area_codes:
                self.results['type'] = 'Landline'
            else:
                self.results['type'] = 'Unknown'
        else:
            self.results['type'] = 'International'
        return self.results.get('type')

    def detect_area(self):
        """تشخیص منطقه برای خطوط ثابت ایران"""
        if self.results.get('country_code') == '98' and len(self.phone) >= 10:
            # پیش‌شماره 3 رقمی بعد از 98
            prefix = self.phone[2:5] if len(self.phone) >= 5 else None
            if prefix and prefix in self.area_codes:
                self.results['area'] = self.area_codes[prefix]
                return self.results['area']
        return None

    def format_number(self):
        """فرمت‌بندی شماره برای نمایش"""
        if self.results.get('country_code') == '98' and len(self.phone) >= 10:
            formatted = f"0{self.phone[1:]}"
            self.results['formatted'] = formatted
            self.results['international'] = f"+{self.phone}"
        else:
            self.results['formatted'] = self.phone
            self.results['international'] = f"+{self.phone}"
        return self.results

    def validate_phone(self):
        """اعتبارسنجی شماره (ساختار و طول)"""
        if self.results.get('country_code') == '98':
            if len(self.phone) == 10:
                self.results['valid'] = True
                self.results['validation_msg'] = 'Valid Iranian phone number (10 digits)'
            elif len(self.phone) == 11 and self.phone.startswith('98'):
                self.results['valid'] = True
                self.results['validation_msg'] = 'Valid Iranian phone number (11 digits, including country code)'
            else:
                self.results['valid'] = False
                self.results['validation_msg'] = 'Invalid Iranian phone number (must be 10 or 11 digits)'
        else:
            if len(self.phone) >= 7 and len(self.phone) <= 15:
                self.results['valid'] = True
                self.results['validation_msg'] = 'Valid international phone number'
            else:
                self.results['valid'] = False
                self.results['validation_msg'] = 'Invalid phone number format'

    def search_truecaller(self):
        """جستجو در Truecaller (API عمومی) - غیرفعال شده به دلیل فیلتر"""
        self.results['truecaller'] = {
            'status': 'disabled',
            'message': 'Truecaller API is blocked in your region. Use alternative methods.'
        }
        log_warning("Truecaller API is blocked. Skipping...")

    def search_google(self):
        """جستجو در گوگل با Dork های ساده"""
        try:
            dorks = [
                f'"{self.phone}"',
                f'"{self.phone}" site:ir',
                f'"{self.phone}" site:telegram.me',
                f'"{self.phone}" site:instagram.com'
            ]
            self.results['google_search'] = {
                'dorks': dorks,
                'message': 'Copy these dorks to search manually in Google'
            }
            log_info(f"Google dorks generated for {self.phone}")
        except Exception as e:
            log_error(f"Google search error: {e}")

    def run(self):
        log_info(f"Starting Phone Info gathering for: {self.phone}")
        
        # تحلیل شماره
        self.detect_country()
        self.format_number()
        self.validate_phone()
        self.get_phone_type()
        self.detect_operator_iran()
        self.detect_area()
        
        # جستجوهای خارجی (اختیاری)
        if self.verbose:
            self.search_truecaller()
            self.search_google()
        
        # نتیجه نهایی
        self.results['phone'] = self.phone
        self.results['scan_type'] = 'phone_info'
        
        log_success("Phone info gathering completed.")
        
        # نمایش نتایج در ترمینال
        log_info("=== Phone Information ===")
        log_info(f"  Number: {self.results.get('formatted', 'N/A')}")
        log_info(f"  International: {self.results.get('international', 'N/A')}")
        log_info(f"  Country: {self.results.get('country', 'Unknown')}")
        log_info(f"  Country Code: +{self.results.get('country_code', 'Unknown')}")
        log_info(f"  Type: {self.results.get('type', 'Unknown')}")
        log_info(f"  Valid: {self.results.get('valid', False)}")
        log_info(f"  Validation: {self.results.get('validation_msg', 'N/A')}")
        if self.results.get('operator'):
            log_info(f"  Operator: {self.results.get('operator')}")
        if self.results.get('area'):
            log_info(f"  Area: {self.results.get('area')}")
        
        return {
            "target": self.phone,
            "scan_type": "phone_info",
            "results": self.results
        }
