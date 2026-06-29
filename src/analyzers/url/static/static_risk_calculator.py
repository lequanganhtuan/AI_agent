from src.core.models import (
    LexicalFeatures,
    BrandAnalysis,
    PatternAnalysis,
    TLDAnalysis,
    TyposquattingAnalysis,
    StaticRiskAnalysis,
)

from src.analyzers.url.static.config import (
    RiskConfig,
)


class StaticRiskCalculator:
    def calculate(self, lexical: LexicalFeatures, brand: BrandAnalysis, pattern: PatternAnalysis, tld: TLDAnalysis, typo: TyposquattingAnalysis) -> StaticRiskAnalysis:
        score = 0
        triggered_signals: list[str] = []
        summary: list[str] = []
        
        # 1. Brand Impersonation Analysis
        if brand.detected_brand and not brand.legitimate_domain_match:
            if brand.brand_in_subdomain:
                score += RiskConfig.BRAND_IN_SUBDOMAIN_WEIGHT
                triggered_signals.append("brand_impersonation_subdomain")
                summary.append(f"Brand '{brand.detected_brand}' appeared in URL subdomain")

            if brand.brand_in_path:
                score += RiskConfig.BRAND_IN_PATH_WEIGHT
                triggered_signals.append("brand_impersonation_path")
                summary.append(f"Brand '{brand.detected_brand}' appeared in URL path")
            
        # 2. Typosquatting Analysis
        if typo.suspicious:
            score += RiskConfig.TYPOSQUATTING_WEIGHT
            triggered_signals.append("typosquatting")
            if typo.target_domain:
                summary.append(f"Domain has signal of typosquatting with '{typo.target_domain}'")       
                
        # Homoglyph Attack Check
        if typo.homoglyph_detected:
            score += RiskConfig.HOMOGLYPH_WEIGHT
            triggered_signals.append("homoglyph_attack")
            summary.append("Detected homoglyph attack")
            
        # 3. Pattern Obfuscation Analysis
        # Lấy số lượng từ khóa linh hoạt (ưu tiên độ dài list nếu count bằng 0)
        keyword_count = pattern.suspicious_keyword_count or len(getattr(pattern, "suspicious_keywords", []))
        
        keyword_score = min(
            keyword_count * RiskConfig.SUSPICIOUS_KEYWORD_WEIGHT, 
            RiskConfig.MAX_KEYWORD_SCORE
        )
        
        if keyword_score > 0:
            score += keyword_score
            triggered_signals.append("suspicious_keywords")
            summary.append(f"Detected {keyword_count} suspicious keywords")
            
        if pattern.encoded_character_detected:
            score += RiskConfig.ENCODED_CHARACTER_WEIGHT
            triggered_signals.append("encoded_characters")
            summary.append("Detected encoded characters")

        if pattern.double_extension_detected:
            score += RiskConfig.DOUBLE_EXTENSION_WEIGHT
            triggered_signals.append("double_extension")
            summary.append("Detected double extension")

        if pattern.suspicious_file_extension:
            score += RiskConfig.SUSPICIOUS_EXTENSION_WEIGHT
            triggered_signals.append("suspicious_extension")
            summary.append("Detected suspicious file extension")

        if pattern.url_shortener_detected:
            score += RiskConfig.URL_SHORTENER_WEIGHT
            triggered_signals.append("url_shortener")
            summary.append("Detected URL shortener")

        if pattern.ip_address_url:
            score += RiskConfig.IP_URL_WEIGHT
            triggered_signals.append("ip_address_url")
            summary.append("IP address used as domain")

        # 4. TLD Risk Analysis
        if tld.high_risk_tld:
            score += RiskConfig.HIGH_RISK_TLD_WEIGHT
            triggered_signals.append("high_risk_tld")
            summary.append(f"High risk TLD: {tld.tld}")
        elif tld.medium_risk_tld:
            score += RiskConfig.MEDIUM_RISK_TLD_WEIGHT
            triggered_signals.append("medium_risk_tld")
            summary.append(f"Medium risk TLD: {tld.tld}")

        # 5. Lexical Structure Analysis (Toán tử >= quét chặt biên giá trị cấu hình)
        if lexical.url_length >= RiskConfig.LONG_URL_THRESHOLD:
            score += RiskConfig.LONG_URL_WEIGHT
            triggered_signals.append("long_url")
            summary.append("URL length exceeds threshold")

        if lexical.domain_entropy >= RiskConfig.ENTROPY_THRESHOLD:
            score += RiskConfig.HIGH_ENTROPY_WEIGHT
            triggered_signals.append("high_entropy")
            summary.append("High domain entropy")

        if lexical.digit_ratio_domain >= RiskConfig.DIGIT_RATIO_THRESHOLD:
            score += RiskConfig.DIGIT_RATIO_WEIGHT
            triggered_signals.append("high_digit_ratio")
            summary.append("High digit ratio in domain")

        if lexical.subdomain_count >= RiskConfig.SUBDOMAIN_THRESHOLD:
            score += RiskConfig.SUBDOMAIN_WEIGHT
            triggered_signals.append("many_subdomains")
            summary.append("High number of subdomains")
            
        # 6. Score Saturation & Classification (Giới hạn trần điểm tối đa là 100)
        score = min(score, 100)
        
        if score >= 70:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
            
        return StaticRiskAnalysis(
            score=score,
            risk_level=risk_level,
            triggered_signals=triggered_signals,
            summary=summary
        )