# coding: utf-8

from datetime import datetime
import re
import socket
from contextlib import contextmanager
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
import urllib.request

import pandas as pd
from bs4 import BeautifulSoup

try:
    import whois
except ImportError:  # Optional fallback; requirements.txt installs python-whois.
    whois = None


WHOIS_TIMEOUT = 4
ALEXA_TIMEOUT = 2


@contextmanager
def _socket_timeout(seconds):
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(seconds)
    try:
        yield
    finally:
        socket.setdefaulttimeout(old_timeout)


class FeatureExtraction:
    def getProtocol(self, url):
        return urlparse(url).scheme

    def getDomain(self, url):
        return urlparse(url).netloc

    def getPath(self, url):
        return urlparse(url).path

    def havingIP(self, url):
        pattern = (
            r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}"
            r"([01]?\d\d?|2[0-4]\d|25[0-5])"
        )
        return 1 if re.search(pattern, url) else 0

    def long_url(self, url):
        length = len(url)
        return 0 if length < 54 else 2 if length <= 75 else 1

    def have_at_symbol(self, url):
        return 1 if "@" in url else 0

    def redirection(self, url):
        return 1 if "//" in urlparse(url).path else 0

    def prefix_suffix_separation(self, url):
        return 1 if "-" in urlparse(url).netloc else 0

    def sub_domains(self, url):
        # Kept consistent with the original model's feature logic.
        dots = url.count(".")
        return 0 if dots < 3 else 2 if dots == 3 else 1

    def shortening_service(self, url):
        pattern = (
            r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|bitly\.com|"
            r"is\.gd|buff\.ly|adf\.ly)"
        )
        return 1 if re.search(pattern, url, flags=re.IGNORECASE) else 0

    def web_traffic(self, url):
        """
        Legacy feature used by the original model.

        The old Alexa endpoint may be unavailable. When unavailable,
        return the original project's neutral fallback value (1).
        """
        try:
            endpoint = (
                "http://data.alexa.com/data?cli=10&dat=s&url="
                + quote(url, safe="")
            )
            response = urllib.request.urlopen(endpoint, timeout=ALEXA_TIMEOUT)
            root = BeautifulSoup(response.read(), "xml")
            reach = root.find("REACH")

            if not reach or not reach.get("RANK"):
                return 1

            return 0 if int(reach["RANK"]) < 100000 else 2
        except (TypeError, ValueError, HTTPError, URLError, OSError):
            return 1

    def _whois(self, domain):
        if whois is None:
            raise RuntimeError("python-whois is not installed")
        with _socket_timeout(WHOIS_TIMEOUT):
            return whois.whois(domain)

    @staticmethod
    def _first_date(value):
        if isinstance(value, list):
            return value[0] if value else None
        return value

    def domain_registration_length(self, url):
        try:
            domain = urlparse(url).hostname
            if not domain:
                return 1

            data = self._whois(domain)
            expiration_date = self._first_date(data.expiration_date)

            if not expiration_date:
                return 1

            today = datetime.now(expiration_date.tzinfo) if getattr(
                expiration_date, "tzinfo", None
            ) else datetime.now()

            registration_length = abs((expiration_date - today).days)
            return 1 if registration_length / 365 <= 1 else 0
        except Exception:
            return 1

    def age_domain(self, url):
        try:
            domain = urlparse(url).hostname
            if not domain:
                return 1

            data = self._whois(domain)
            creation_date = self._first_date(data.creation_date)
            expiration_date = self._first_date(data.expiration_date)

            if not creation_date or not expiration_date:
                return 1

            age_of_domain = abs((expiration_date - creation_date).days)
            return 1 if (age_of_domain / 30) < 6 else 0
        except Exception:
            return 1

    def dns_record(self, url):
        try:
            domain = urlparse(url).hostname
            if not domain:
                return 1

            self._whois(domain)
            return 0
        except Exception:
            return 1

    def statistical_report(self, url):
        hostname = urlparse(url).hostname or ""

        suspicious_keywords = (
            r"at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|"
            r"hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly"
        )

        known_ips = (
            r"146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88"
        )

        try:
            ip_address = socket.gethostbyname(hostname)

            if (
                re.search(suspicious_keywords, url, flags=re.IGNORECASE)
                or re.search(known_ips, ip_address)
            ):
                return 1

            return 0
        except (OSError, socket.gaierror):
            return 1

    def https_token(self, url):
        try:
            match = re.search(r"https?://", url, flags=re.IGNORECASE)

            if not match:
                return 0

            rest = url[match.end():]
            return 1 if re.search(r"https?", rest, flags=re.IGNORECASE) else 0
        except Exception:
            return 1


def getAttributess(url):
    fe = FeatureExtraction()

    features = {
        "Having_@_symbol": fe.have_at_symbol(url),
        "Having_IP": fe.havingIP(url),
        "Prefix_suffix_separation": fe.prefix_suffix_separation(url),
        "Redirection_//_symbol": fe.redirection(url),
        "Sub_domains": fe.sub_domains(url),
        "URL_Length": fe.long_url(url),
        "Age_Domain": fe.age_domain(url),
        "DNS_Record": fe.dns_record(url),
        "Domain_Registration_Length": fe.domain_registration_length(url),
        "HTTPS_Token": fe.https_token(url),
        "Statistical_Report": fe.statistical_report(url),
        "Tiny_URL": fe.shortening_service(url),
        "Web_Traffic": fe.web_traffic(url),
    }

    return pd.DataFrame([features])
