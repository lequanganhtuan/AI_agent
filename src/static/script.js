document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyze-form');
    const input = document.getElementById('url-input');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('spinner');
    const errorMsg = document.getElementById('error-message');
    const resultsSection = document.getElementById('results-section');
    
    // Tab Elements
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    // Static Results elements
    const scorePath = document.getElementById('score-path');
    const scoreValue = document.getElementById('score-value');
    const riskLevelText = document.getElementById('risk-level-text');
    const scoreCard = document.getElementById('score-card');

    // Threat Intel Results elements
    const threatScorePath = document.getElementById('threat-score-path');
    const threatScoreValue = document.getElementById('threat-score-value');
    const threatRiskLevelText = document.getElementById('threat-risk-level-text');
    const threatScoreCard = document.getElementById('threat-score-card');
    const threatConfidence = document.getElementById('threat-confidence');
    const triggeredSignalsContainer = document.getElementById('triggered-signals-container');
    const threatSummaryDetails = document.getElementById('threat-summary-details');

    // Tab Switching Logic
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.add('hidden'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-tab');
            document.getElementById(targetId).classList.remove('hidden');
        });
    });
    
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
            
            displayResults(data);
            
        } catch (error) {
            errorMsg.textContent = error.message;
            errorMsg.classList.remove('hidden');
        } finally {
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
            input.disabled = false;
        }
    });
    
    function displayResults(data) {
        // --- 1. POPULATE STATIC ANALYSIS TAB ---
        const staticRisk = data.static.risk;
        const staticScore = staticRisk.score;
        const staticLevel = staticRisk.risk_level;
        
        // Update Static Progress Circle Gauge
        setTimeout(() => {
            scorePath.setAttribute('stroke-dasharray', `${staticScore}, 100`);
            animateValue(scoreValue, 0, staticScore, 1000);
        }, 100);
        
        // Update Static Card Risk Themes
        scoreCard.className = 'score-card';
        scoreCard.classList.add(`theme-${staticLevel}`);
        riskLevelText.textContent = staticLevel;
        
        // Populate static components lists
        populateList('list-lexical', getLexicalSummary(data.static.lexical));
        populateList('list-brand', getBrandSummary(data.static.brand));
        populateList('list-pattern', getPatternSummary(data.static.pattern));
        populateList('list-tld', getTLDSummary(data.static.tld));
        populateList('list-typo', getTypoSummary(data.static.typosquatting));

        // --- 2. POPULATE THREAT INTELLIGENCE (PHASE 3) TAB ---
        const threatRisk = data.threat_intel.risk;
        const threatScore = threatRisk.score;
        const threatLevel = threatRisk.risk_level;
        const confidenceVal = Math.round(threatRisk.confidence * 100);

        // Update Threat Circle Gauge (compounded score is max 80, map it out of 80 visually or normalized as fraction)
        // Let's normalize it to 100 for visual consistency: (threatScore / 80) * 100
        const normalizedThreatScore = Math.min(100, Math.round((threatScore / 80) * 100));
        setTimeout(() => {
            threatScorePath.setAttribute('stroke-dasharray', `${normalizedThreatScore}, 100`);
            animateValue(threatScoreValue, 0, threatScore, 1000);
        }, 100);

        // Update Threat Card Risk Themes
        threatScoreCard.className = 'score-card';
        threatScoreCard.classList.add(`theme-${threatLevel}`);
        threatRiskLevelText.textContent = threatLevel;
        threatConfidence.textContent = `${confidenceVal}%`;

        // Populate Triggered Signals
        triggeredSignalsContainer.innerHTML = '';
        const signals = threatRisk.triggered_signals || [];
        if (signals.length === 0) {
            triggeredSignalsContainer.innerHTML = '<span class="no-signals">No suspicious signals detected.</span>';
        } else {
            signals.forEach(sig => {
                const span = document.createElement('span');
                span.textContent = sig;
                span.className = 'badge';
                
                // Add color class depending on signal severity code
                if (['BLACKLIST_MATCH', 'VT_MALICIOUS', 'GOOGLE_BLACKLIST', 'URLHAUS_MALWARE'].includes(sig)) {
                    span.classList.add('badge-danger');
                } else if (['MANY_REDIRECTS', 'MALICIOUS_DOM', 'HIGH_FRAUD_SCORE', 'TOR_EXIT_NODE'].includes(sig)) {
                    span.classList.add('badge-warning');
                } else {
                    span.classList.add('badge-info');
                }
                triggeredSignalsContainer.appendChild(span);
            });
        }

        // Populate Explanation Summary Bullets
        threatSummaryDetails.innerHTML = '';
        const summaryText = threatRisk.summary || '';
        const summaryLines = summaryText.split('\n').map(l => l.trim()).filter(l => l.length > 0);
        if (summaryLines.length === 0) {
            threatSummaryDetails.innerHTML = '<p class="clean-summary">No threats found.</p>';
        } else {
            const ul = document.createElement('ul');
            ul.className = 'summary-list';
            summaryLines.forEach(line => {
                const li = document.createElement('li');
                // Remove checkmark character if it already exists because CSS adds it
                li.textContent = line.startsWith('✓') ? line.substring(1).trim() : line;
                ul.appendChild(li);
            });
            threatSummaryDetails.appendChild(ul);
        }

        // Populate Engine Cards
        populateEngineVT(data.threat_intel.virustotal, threatRisk.provider_hits.virustotal);
        populateEngineGSB(data.threat_intel.google_safe_browsing, threatRisk.provider_hits.google_safe_browsing);
        populateEngineURLHaus(data.threat_intel.urlhaus, threatRisk.provider_hits.urlhaus);
        populateEngineURLScan(data.threat_intel.urlscan, threatRisk.provider_hits.urlscan);
        populateEngineAbuseIPDB(data.threat_intel.ip_reputation, threatRisk.provider_hits.ip_reputation);
        
        // Show results
        resultsSection.classList.remove('hidden');
    }
    
    // --- VALUE ANIMATION HELPER ---
    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.textContent = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            } else {
                obj.textContent = end;
            }
        };
        window.requestAnimationFrame(step);
    }

    // --- ENGINE SPECIFIC INJECTORS ---
    // --- GENERIC ERROR HANDLER ---
    function handleEngineError(card, status, detail, dataObj) {
        card.className = 'engine-card border-warning';
        status.textContent = 'API Error';
        status.className = 'status-pill status-warning';
        
        let msg = 'Provider lookup failed';
        if (dataObj && dataObj.error_message) {
            const err = dataObj.error_message.toLowerCase();
            if (err.includes('insufficient credits') || err.includes('credit')) {
                msg = 'Insufficient Credits';
            } else if (err.includes('unauthorized') || err.includes('401') || err.includes('auth')) {
                msg = 'Invalid API Key (Unauthorized)';
            } else if (err.includes('blocked') || err.includes('prevented')) {
                msg = 'Scan Blocked / Restricted';
            } else if (err.includes('timeout') || err.includes('connection')) {
                msg = 'Connection Timeout';
            } else {
                msg = dataObj.error_message.length > 50 ? dataObj.error_message.substring(0, 50) + '...' : dataObj.error_message;
            }
        }
        detail.textContent = msg;
    }

    // --- ENGINE SPECIFIC INJECTORS ---
    function populateEngineVT(vt, isHit) {
        const status = document.getElementById('engine-vt-status');
        const detail = document.getElementById('engine-vt-detail');
        const card = document.getElementById('card-vt');

        card.className = 'engine-card';
        if (vt && vt.error_message) {
            handleEngineError(card, status, detail, vt);
            return;
        }
        if (isHit && vt && vt.malicious > 0) {
            status.textContent = 'Malicious';
            status.className = 'status-pill status-danger';
            detail.textContent = `${vt.malicious} / ${vt.total_engines || 0} malicious engines`;
            card.classList.add('border-danger');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = '0 flagged engines';
        }
    }

    function populateEngineGSB(gsb, isHit) {
        const status = document.getElementById('engine-gsb-status');
        const detail = document.getElementById('engine-gsb-detail');
        const card = document.getElementById('card-gsb');

        card.className = 'engine-card';
        if (gsb && gsb.error_message) {
            handleEngineError(card, status, detail, gsb);
            return;
        }
        if (isHit && gsb && gsb.threat_found) {
            status.textContent = 'Malicious';
            status.className = 'status-pill status-danger';
            detail.textContent = `Threat type: ${gsb.threat_type || 'Malware'}`;
            card.classList.add('border-danger');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = 'No listing found';
        }
    }

    function populateEngineURLHaus(uh, isHit) {
        const status = document.getElementById('engine-urlhaus-status');
        const detail = document.getElementById('engine-urlhaus-detail');
        const card = document.getElementById('card-urlhaus');

        card.className = 'engine-card';
        if (uh && uh.error_message) {
            handleEngineError(card, status, detail, uh);
            return;
        }
        if (isHit && uh && uh.query_status === 'ok') {
            status.textContent = 'Malicious';
            status.className = 'status-pill status-danger';
            detail.textContent = `Flagged as: ${uh.threat || 'malware'}`;
            card.classList.add('border-danger');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = 'No listing found';
        }
    }

    function populateEngineURLScan(us, isHit) {
        const status = document.getElementById('engine-urlscan-status');
        const detail = document.getElementById('engine-urlscan-detail');
        const card = document.getElementById('card-urlscan');

        card.className = 'engine-card';
        if (us && us.error_message) {
            handleEngineError(card, status, detail, us);
            return;
        }

        const globalScore = us ? us.malicious_score || 0 : 0;
        const localScore = us ? Math.round((us.final_local_score || 0) * 100) : 0;
        const formScore = us ? Math.round((us.form_risk_score || 0) * 100) : 0;
        const hostingScore = us ? Math.round((us.hosting_risk_score || 0) * 100) : 0;
        
        // Max risk score across global and local heuristics
        const maxScore = Math.max(globalScore, localScore, formScore, hostingScore);

        if (isHit || maxScore >= 40) {
            const isMalicious = globalScore >= 80 || localScore >= 70 || formScore >= 80;
            status.textContent = isMalicious ? 'Malicious' : 'Suspicious';
            status.className = `status-pill status-${isMalicious ? 'danger' : 'warning'}`;
            
            let explanation = `Risk score: ${maxScore}%`;
            if (us && us.redirect_count > 0) {
                explanation += ` (${us.redirect_count} redirects)`;
            }
            detail.textContent = explanation;
            card.classList.add(isMalicious ? 'border-danger' : 'border-warning');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = `Score: ${globalScore}% (no threats)`;
        }
    }

    function populateEngineAbuseIPDB(ab, isHit) {
        const status = document.getElementById('engine-abuseipdb-status');
        const detail = document.getElementById('engine-abuseipdb-detail');
        const card = document.getElementById('card-abuseipdb');

        card.className = 'engine-card';
        if (ab && ab.error_message) {
            handleEngineError(card, status, detail, ab);
            return;
        }
        const score = ab ? ab.abuse_score || 0 : 0;
        if (isHit || score >= 40) {
            const isMalicious = score >= 80;
            status.textContent = isMalicious ? 'Malicious' : 'Suspicious';
            status.className = `status-pill status-${isMalicious ? 'danger' : 'warning'}`;
            
            let explanation = `Confidence score: ${score}%`;
            if (ab && ab.total_reports > 0) {
                explanation += ` (${ab.total_reports} reports)`;
            }
            detail.textContent = explanation;
            card.classList.add(isMalicious ? 'border-danger' : 'border-warning');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = `Confidence score: ${score}%`;
        }
    }

    // --- LIST BUILDERS ---
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
    
    // --- HELPER CONTEXT GENERATORS ---
    function getLexicalSummary(data) {
        const findings = [];
        if (data.url_length > 100) findings.push(`Long URL detected (${data.url_length} chars)`);
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
