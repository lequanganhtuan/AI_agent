from __future__ import annotations
from typing import Any
import urllib.parse
from bs4 import BeautifulSoup
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig
from src.analyzers.url.dynamic_analysis.utils.url_utils import get_apex_domain

class FormDetector:
    """Detector for identifying forms, structural inputs, and exfiltration characteristics."""

    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()

    def detect(self, soup: BeautifulSoup, page_url: str = "") -> dict[str, Any]:
        forms = soup.find_all("form")
        form_count = len(forms)
        
        has_login_form = False
        has_password_field = False
        has_otp_field = False
        has_cccd_field = False
        has_credit_card_field = False
        
        form_actions = []
        has_cross_domain_form = False
        has_insecure_form_action = False
        has_get_login_form = False
        has_empty_action_form = False

        # Extract page domain details if provided
        page_apex = get_apex_domain(page_url) if page_url else ""
        
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

        # Check forms actions, methods, and types
        for form in forms:
            action = form.get("action")
            method = (form.get("method") or "get").lower()
            
            # Check if login form is present
            has_form_pwd = bool(form.find("input", type="password"))
            form_id = (form.get("id") or "").lower()
            form_name = (form.get("name") or "").lower()
            form_action_str = (action or "").lower()
            
            is_sensitive_form = has_form_pwd or any(
                kw in form_id or kw in form_name or kw in form_action_str for kw in self.config.LOGIN_KEYWORDS
            )
            if is_sensitive_form:
                has_login_form = True

            # 1. Empty or "#" action target
            if not action or action.strip() in ["", "#"]:
                has_empty_action_form = True
                form_actions.append("")
            else:
                form_actions.append(action)
                # Resolve relative action URL using the page URL
                if page_url:
                    abs_action = urllib.parse.urljoin(page_url, action)
                    action_apex = get_apex_domain(abs_action)
                    
                    # 2. Cross-domain exfiltration
                    if action_apex and page_apex and action_apex.lower() != page_apex.lower():
                        has_cross_domain_form = True
                        
                    # 3. Insecure submission protocol
                    if abs_action.startswith("http://"):
                        has_insecure_form_action = True
                else:
                    # Fallback check for absolute insecure action
                    if action.startswith("http://"):
                        has_insecure_form_action = True

            # 4. HTTP GET method on sensitive form
            if method == "get" and is_sensitive_form:
                has_get_login_form = True

        return {
            "form_count": form_count,
            "has_login_form": has_login_form,
            "has_password_field": has_password_field,
            "has_otp_field": has_otp_field,
            "has_cccd_field": has_cccd_field,
            "has_credit_card_field": has_credit_card_field,
            "form_actions": form_actions,
            "has_cross_domain_form": has_cross_domain_form,
            "has_insecure_form_action": has_insecure_form_action,
            "has_get_login_form": has_get_login_form,
            "has_empty_action_form": has_empty_action_form
        }
