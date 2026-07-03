LLM_JSON_SCHEMA = """
{
  "type": "object",
  "properties": {
    "website_purpose": {
      "type": "string",
      "description": "A concise description of the website's primary purpose and intent."
    },
    "is_phishing": {
      "type": "boolean",
      "description": "Whether the website is determined to be a phishing attempt."
    },
    "fraud_category": {
      "type": "string",
      "enum": ["PHISHING", "SCAM", "MALWARE", "BRAND_IMPERSONATION", "LEGITIMATE", "OTHER"],
      "description": "The primary fraud classification category for the analyzed website."
    },
    "detected_brand": {
      "type": ["string", "null"],
      "description": "The legitimate brand being impersonated, if any. Null if no brand impersonation is detected."
    },
    "brand_confidence": {
      "type": "number",
      "minimum": 0.0,
      "maximum": 1.0,
      "description": "Confidence score for the brand detection, ranging from 0.0 (no confidence) to 1.0 (absolute certainty)."
    },
    "reasoning": {
      "type": "array",
      "items": { "type": "string" },
      "description": "A list of discrete analytical observations supporting the classification decision. Each entry must cite specific evidence."
    },
    "summary": {
      "type": "string",
      "description": "A comprehensive narrative summary of the overall analysis findings and conclusion."
    },
    "recommended_action": {
      "type": "string",
      "enum": ["BLOCK", "WARN", "MONITOR", "ALLOW"],
      "description": "The recommended security action to take for the analyzed URL."
    },
    "risk_level": {
      "type": "string",
      "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      "description": "The categorical risk classification. Do NOT return a numeric score."
    },
    "findings": {
      "type": "array",
      "items": { "type": "string" },
      "description": "A list of specific threat indicators, suspicious elements, or notable observations discovered during analysis."
    }
  },
  "required": [
    "website_purpose",
    "is_phishing",
    "fraud_category",
    "detected_brand",
    "brand_confidence",
    "reasoning",
    "summary",
    "recommended_action",
    "risk_level",
    "findings"
  ]
}
"""
