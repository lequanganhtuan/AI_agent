from src.core.models import (
    ValidationResult,
    BrandAnalysis,
)
from src.analyzers.url.static.config import (
    BrandConfig,
)

class BrandAnalyzer:
    
    def analyze(self, validation_result: ValidationResult) -> BrandAnalysis:
        components = validation_result.components
        
        if not components:
            raise ValueError(
                "ValidationResult must contain URL components."
            )
            
        full_domain = components.full_domain.lower()
        sub_domain = components.subdomain.lower()
        path = components.path.lower()
        
        # 1. Phát hiện xem URL có chứa từ khóa của thương hiệu nào không
        detected_brand = self._detect_brand(
            full_domain,
            path,
        )
        
        if not detected_brand:
            return BrandAnalysis()
        
        # 2. Kiểm tra xem domain hiện tại có thuộc danh sách nền tảng uy tín (Whitelist) không
        is_trusted_platform = any(
            full_domain == platform or full_domain.endswith(f".{platform}")
            for platform in getattr(BrandConfig, "TRUSTED_PLATFORMS", set())
        )
        
        # 3. Tính toán các cờ logic liên quan đến Brand
        brand_in_subdomain = self._brand_in_subdomain(detected_brand, sub_domain)
        legitimate_domain_match = self._is_legitimate_domain(detected_brand, full_domain)
        
        # CHỐT CHẶN BẢO VỆ: Nếu nằm trên nền tảng uy tín (như github.com), KHÔNG phạt lỗi brand_in_path
        if is_trusted_platform:
            brand_in_path = False
        else:
            brand_in_path = self._brand_in_path(detected_brand, path)
        
        return BrandAnalysis(
            detected_brand=detected_brand,
            brand_in_subdomain=brand_in_subdomain,
            brand_in_path=brand_in_path,
            legitimate_domain_match=legitimate_domain_match
        )
    
    @staticmethod
    def _detect_brand(full_domain: str, path: str) -> str | None:
        for brand in BrandConfig.BRAND_KEYWORDS:
            brand_lower = brand.lower()
            if brand_lower in full_domain or brand_lower in path:
                return brand_lower
            
        return None 
    
    @staticmethod
    def _brand_in_subdomain(brand: str, subdomain: str) -> bool:
        return brand in subdomain
    
    @staticmethod
    def _brand_in_path(brand: str, path: str) -> bool:
        return brand in path
    
    @staticmethod
    def _is_legitimate_domain(brand: str, full_domain: str) -> bool:
        legitimate_domains = BrandConfig.LEGITIMATE_DOMAINS.get(brand, set())
        legitimate_domains_lower = {d.lower() for d in legitimate_domains}
        
        if full_domain in legitimate_domains_lower:
            return True   
        for legit_domain in legitimate_domains_lower:
            if full_domain.endswith(f".{legit_domain}"):
                return True
                
        return False