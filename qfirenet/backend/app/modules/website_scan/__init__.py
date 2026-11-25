# Website Scan sub-package
# Exports the four check functions for easy import elsewhere
from .ssl_check import check_ssl
from .whois_check import check_whois
from .phishing_check import check_phishing_heuristics
from .pqc_check import check_pqc_readiness

__all__ = ["check_ssl", "check_whois", "check_phishing_heuristics", "check_pqc_readiness"]
