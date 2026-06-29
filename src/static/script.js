document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyze-form');
    const input = document.getElementById('url-input');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('spinner');
    const errorMsg = document.getElementById('error-message');
    const resultsSection = document.getElementById('results-section');
    
    // Results elements
    const scorePath = document.getElementById('score-path');
    const scoreValue = document.getElementById('score-value');
    const riskLevelText = document.getElementById('risk-level-text');
    const scoreCard = document.getElementById('score-card');
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const url = input.value.trim();
        if (!url) return;
        
        // Reset UI
        errorMsg.classList.add('hidden');
        resultsSection.classList.add('hidden');
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        input.disabled = true;
        
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.detail || 'Failed to analyze URL');
            }
            
            displayResults(data.static.risk, data.static);
            
        } catch (error) {
            errorMsg.textContent = error.message;
            errorMsg.classList.remove('hidden');
        } finally {
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
            input.disabled = false;
        }
    });
    
    function displayResults(riskData, fullData) {
        const score = riskData.score;
        const riskLevel = riskData.risk_level;
        
        // Update Score Circular Progress
        // stroke-dasharray = "score, 100" where score is percentage
        setTimeout(() => {
            scorePath.setAttribute('stroke-dasharray', `${score}, 100`);
            
            // Animate number
            let current = 0;
            const step = Math.max(1, Math.floor(score / 30));
            const timer = setInterval(() => {
                current += step;
                if (current >= score) {
                    current = score;
                    clearInterval(timer);
                }
                scoreValue.textContent = current;
            }, 20);
        }, 100);
        
        // Update Theme & Risk Level Text
        scoreCard.classList.remove('theme-low', 'theme-medium', 'theme-high');
        scoreCard.classList.add(`theme-${riskLevel}`);
        riskLevelText.textContent = riskLevel;
        
        // Populate Phases Data (We don't have detailed breakdown of signals per phase in the response,
        // but the StaticRiskCalculator puts all summaries in `risk.summary`.
        // To make it look good, let's distribute the findings or check the actual signals.
        // Actually, the StaticAnalysisResult has full lexical, brand, pattern objects.
        // But for this demo, let's just populate based on what's triggered.
        
        populateList('list-lexical', getLexicalSummary(fullData.lexical));
        populateList('list-brand', getBrandSummary(fullData.brand));
        populateList('list-pattern', getPatternSummary(fullData.pattern));
        populateList('list-tld', getTLDSummary(fullData.tld));
        populateList('list-typo', getTypoSummary(fullData.typosquatting));
        
        // Show results
        resultsSection.classList.remove('hidden');
    }
    
    function populateList(elementId, items) {
        const ul = document.getElementById(elementId);
        ul.innerHTML = '';
        
        if (!items || items.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No suspicious findings.';
            li.className = 'no-findings';
            ul.appendChild(li);
            return;
        }
        
        items.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            ul.appendChild(li);
        });
    }
    
    // Helper functions to extract summary points from the phase data
    // Since StaticAnalysisResult models don't have direct summary arrays, we infer from flags.
    
    function getLexicalSummary(data) {
        const findings = [];
        if (data.url_length > 100) findings.push(`Long URL detected (${data.url_length} chars)`); // Arbitrary threshold for demo if config not exposed
        if (data.subdomain_count >= 2) findings.push(`Multiple subdomains (${data.subdomain_count})`);
        if (data.digit_ratio_domain > 0.3) findings.push(`High digit ratio (${(data.digit_ratio_domain*100).toFixed(0)}%)`);
        return findings;
    }
    
    function getBrandSummary(data) {
        const findings = [];
        if (data.detected_brand) findings.push(`Detected brand: ${data.detected_brand}`);
        if (data.brand_in_subdomain) findings.push(`Brand found in subdomain`);
        if (data.homoglyph_detected) findings.push(`Homoglyph attack detected`);
        return findings;
    }
    
    function getPatternSummary(data) {
        const findings = [];
        if (data.suspicious_keyword_count > 0) findings.push(`Found ${data.suspicious_keyword_count} suspicious keywords`);
        if (data.encoded_character_detected) findings.push(`Encoded characters detected`);
        if (data.double_extension_detected) findings.push(`Double extension found`);
        if (data.ip_address_url) findings.push(`IP address used as domain`);
        if (data.url_shortener_detected) findings.push(`URL shortener used`);
        return findings;
    }
    
    function getTLDSummary(data) {
        const findings = [];
        if (data.tld) findings.push(`TLD: .${data.tld}`);
        if (data.high_risk_tld) findings.push(`High risk TLD`);
        if (data.medium_risk_tld) findings.push(`Medium risk TLD`);
        return findings;
    }
    
    function getTypoSummary(data) {
        const findings = [];
        if (data.suspicious) findings.push(`Suspicious typosquatting pattern`);
        if (data.target_domain) findings.push(`Similar to: ${data.target_domain}`);
        if (data.homoglyph_detected) findings.push(`Homoglyph usage found`);
        return findings;
    }
});
