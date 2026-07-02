from __future__ import annotations
from typing import Any
from bs4 import BeautifulSoup
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig

class FormDetector:
    """Detector for identifying forms and structural inputs (password, OTP, CCCD, credit card fields)."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()

    def detect(self, soup: BeautifulSoup) -> dict[str, Any]:
        forms = soup.find_all("form")
        form_count = len(forms)
        
        has_login_form = False
        has_password_field = False
        has_otp_field = False
        has_cccd_field = False
        has_credit_card_field = False
        
        # Check all input elements
        inputs = soup.find_all("input")
        for inp in inputs:
            inp_type = (inp.get("type") or "").lower()
            inp_name = (inp.get("name") or "").lower()
            inp_id = (inp.get("id") or "").lower()
            inp_placeholder = (inp.get("placeholder") or "").lower()
            
            # Check password
            if inp_type == "password":
                has_password_field = True
                
            # Check OTP
            if any(kw in inp_name or kw in inp_id or kw in inp_placeholder or kw in inp_type for kw in self.config.OTP_KEYWORDS):
                has_otp_field = True
                
            # Check CCCD (National ID)
            if any(kw in inp_name or kw in inp_id or kw in inp_placeholder for kw in self.config.CCCD_KEYWORDS):
                has_cccd_field = True
                
            # Check Credit Card
            if any(kw in inp_name or kw in inp_id or kw in inp_placeholder for kw in self.config.CREDIT_CARD_KEYWORDS):
                has_credit_card_field = True

        # Check if login form is present
        for form in forms:
            # Check if form contains password input
            if form.find("input", type="password"):
                has_login_form = True
                break
            # Or has login/signin id/name/action attributes
            form_id = (form.get("id") or "").lower()
            form_name = (form.get("name") or "").lower()
            form_action = (form.get("action") or "").lower()
            if any(kw in form_id or kw in form_name or kw in form_action for kw in self.config.LOGIN_KEYWORDS):
                has_login_form = True
                break

        return {
            "form_count": form_count,
            "has_login_form": has_login_form,
            "has_password_field": has_password_field,
            "has_otp_field": has_otp_field,
            "has_cccd_field": has_cccd_field,
            "has_credit_card_field": has_credit_card_field
        }
