document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const detailsSubtitle = document.getElementById('details-subtitle');
    const detailsLoading = document.getElementById('details-loading');
    const detailsError = document.getElementById('details-error');
    const resultsSection = document.getElementById('results-section');

    const scorePath = document.getElementById('score-path');
    const scoreValue = document.getElementById('score-value');
    const riskLevelText = document.getElementById('risk-level-text');
    const mainScoreCard = document.getElementById('main-score-card');
    const verdictBadge = document.getElementById('verdict-badge');

    // Extract ID and fetch
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('id');

    if (!scanId) {
        showError('No scan ID provided in the URL query parameters.');
    } else {
        loadScanDetails(scanId);
    }

    async function loadScanDetails(id) {
        try {
            const response = await fetch(`/api/history/${id}`);
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error('Historical report record not found.');
                }
                throw new Error('Failed to retrieve historical record telemetry.');
            }

            const data = await response.json();
            detailsSubtitle.textContent = data.url || data.normalized_url;

            displayResults(data);

            detailsLoading.classList.add('hidden');
            resultsSection.classList.remove('hidden');

        } catch (err) {
            showError(err.message);
        }
    }

    function showError(msg) {
        detailsLoading.classList.add('hidden');
        detailsError.textContent = msg;
        detailsError.classList.remove('hidden');
    }

    function displayResults(data) {
        // 1. COMPOUNDED RISK SCORE & VERDICT RESOLUTION
        const threatRisk = data.threat_intelligence?.risk || data.threat_intel?.risk;
        const score = threatRisk ? threatRisk.score : 0;
        const riskLevel = (threatRisk ? threatRisk.risk_level : 'low').toLowerCase();

        // Animate the risk score gauge circle
        setTimeout(() => {
            scorePath.setAttribute('stroke-dasharray', `${Math.min(100, score)}, 100`);
            animateValue(scoreValue, 0, score, 1000);
        }, 100);

        // Apply risk level themes
        mainScoreCard.className = 'score-card';
        mainScoreCard.classList.add(`theme-${riskLevel}`);
        riskLevelText.textContent = riskLevel;

        // Apply action badge styling
        const action = data.ai?.content?.recommended_action || (score >= 70 ? 'BLOCK' : score >= 40 ? 'WARN' : 'ALLOW');
        verdictBadge.textContent = action;
        verdictBadge.className = 'status-pill';
        if (action === 'BLOCK') {
            verdictBadge.style.background = 'rgba(239, 68, 68, 0.15)';
            verdictBadge.style.color = '#ef4444';
            verdictBadge.style.border = '1px solid rgba(239, 68, 68, 0.3)';
        } else if (action === 'WARN') {
            verdictBadge.style.background = 'rgba(245, 158, 11, 0.15)';
            verdictBadge.style.color = '#f59e0b';
            verdictBadge.style.border = '1px solid rgba(245, 158, 11, 0.3)';
        } else {
            verdictBadge.style.background = 'rgba(16, 185, 129, 0.15)';
            verdictBadge.style.color = '#10b981';
            verdictBadge.style.border = '1px solid rgba(16, 185, 129, 0.3)';
        }

        // 2. AI CONTENT ANALYSIS & EXPLANATION
        const aiResult = data.ai || {};
        document.getElementById('ai-website-purpose').textContent = aiResult.content?.website_purpose || '-';
        document.getElementById('ai-detected-brand').textContent = aiResult.content?.detected_brand || 'None';
        document.getElementById('ai-fraud-category').textContent = aiResult.content?.fraud_category || '-';
        
        const summaryText = aiResult.content?.summary || threatRisk?.summary || 'No AI safety description compiled.';
        document.getElementById('ai-summary-text').textContent = summaryText;

        // Populate AI Findings list
        const findingsDetails = document.getElementById('ai-findings-details');
        findingsDetails.innerHTML = '';
        const findings = aiResult.content?.findings || aiResult.content?.reasoning || [];
        if (findings.length === 0) {
            findingsDetails.innerHTML = '<div class="bullet-item">No AI findings generated.</div>';
        } else {
            const ul = document.createElement('ul');
            ul.className = 'summary-list';
            findings.forEach(f => {
                const li = document.createElement('li');
                li.textContent = f;
                ul.appendChild(li);
            });
            findingsDetails.appendChild(ul);
        }

        // 3. EVIDENCE & TRIGGERED INDICATORS
        const signalsContainer = document.getElementById('triggered-signals-container');
        signalsContainer.innerHTML = '';
        
        // Collate indicators from static, threat, dynamic and AI
        const collatedSignals = new Set();
        
        if (data.validation?.signals) {
            data.validation.signals.forEach(s => collatedSignals.add(s));
        }
        if (data.static?.risk?.triggered_signals) {
            data.static.risk.triggered_signals.forEach(s => collatedSignals.add(s));
        }
        if (threatRisk?.triggered_signals) {
            threatRisk.triggered_signals.forEach(s => collatedSignals.add(s));
        }
        if (data.dynamic?.signals) {
            data.dynamic.signals.forEach(s => {
                if (typeof s === 'string') collatedSignals.add(s);
                else if (s && s.signal) collatedSignals.add(s.signal);
            });
        }
        if (aiResult.signals) {
            aiResult.signals.forEach(s => {
                if (typeof s === 'string') collatedSignals.add(s);
                else if (s && s.signal) collatedSignals.add(s.signal);
            });
        }

        if (collatedSignals.size === 0) {
            signalsContainer.innerHTML = '<span class="no-signals" style="color: var(--text-muted); font-size: 0.95rem;">No security indicators triggered.</span>';
        } else {
            collatedSignals.forEach(sig => {
                const span = document.createElement('span');
                span.textContent = sig;
                span.className = 'badge';

                if (['BLACKLIST_MATCH', 'VT_MALICIOUS', 'GOOGLE_BLACKLIST', 'URLHAUS_MALWARE'].includes(sig)) {
                    span.classList.add('badge-danger');
                } else if (['MANY_REDIRECTS', 'MALICIOUS_DOM', 'HIGH_FRAUD_SCORE', 'TOR_EXIT_NODE'].includes(sig)) {
                    span.classList.add('badge-warning');
                } else {
                    span.classList.add('badge-info');
                }
                signalsContainer.appendChild(span);
            });
        }

        // 4. WEBSITE SCREENSHOT SECTION (WITH PERFORMANCE BYPASS DETECTION)
        const screenshotImg = document.getElementById('dynamic-screenshot-img');
        const screenshotPlaceholder = document.getElementById('dynamic-screenshot-placeholder');
        const screenshotStatus = document.getElementById('screenshot-status-text');

        const dynamicResult = data.dynamic || {};
        
        if (dynamicResult.screenshot_path) {
            screenshotImg.src = dynamicResult.screenshot_path;
            screenshotImg.classList.remove('hidden');
            screenshotPlaceholder.classList.add('hidden');
        } else {
            screenshotImg.classList.add('hidden');
            screenshotPlaceholder.classList.remove('hidden');
            
            // Decipher if skipped in Tier 2 to optimize request latency or if sandbox execution simply failed
            if (data.control?.should_skip_dynamic) {
                screenshotStatus.innerHTML = `
                    <span style="display: block; font-weight: 600; color: #60a5fa; margin-bottom: 5px;">Sandbox Bypassed</span>
                    Crawling skipped to optimize performance (Threat intelligence resolved a definitive verdict in Tier 2).
                `;
            } else if (dynamicResult.status === 'failed') {
                screenshotStatus.innerHTML = `
                    <span style="display: block; font-weight: 600; color: #ef4444; margin-bottom: 5px;">Scraper Timeout</span>
                    Playwright sandbox failed to crawl the page or capture visual assets.
                `;
            } else {
                screenshotStatus.textContent = 'No Screenshot Captured (Dynamic Scraper bypassed).';
            }
        }

        // 5. THREAT PROVIDER VERDICTS
        const ti = data.threat_intelligence || data.threat_intel || {};
        populateEngineVT(ti.virustotal, threatRisk?.provider_hits?.virustotal);
        populateEngineGSB(ti.google_safe_browsing, threatRisk?.provider_hits?.google_safe_browsing);
        populateEngineURLHaus(ti.urlhaus, threatRisk?.provider_hits?.urlhaus);
        populateEngineURLScan(ti.urlscan, threatRisk?.provider_hits?.urlscan);
        populateEngineAbuseIPDB(ti.ip_reputation, threatRisk?.provider_hits?.ip_reputation);
        populateEnginePhishTank(ti.phishtank, threatRisk?.provider_hits?.phishtank);
    }

    // --- RENDER HELPERS ---
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

    function handleEngineError(card, status, detail, dataObj) {
        card.className = 'engine-card border-warning';
        status.textContent = 'API Error';
        status.className = 'status-pill status-warning';
        detail.textContent = dataObj?.error_message || 'Lookup failed';
    }

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
            detail.textContent = `${vt.malicious} / ${vt.total_engines || 0} flagged engines`;
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
            detail.textContent = 'No threats found';
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
            detail.textContent = 'No threats found';
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
        const maxScore = Math.max(globalScore, localScore, formScore);

        if (isHit || maxScore >= 40) {
            const isMalicious = maxScore >= 75;
            status.textContent = isMalicious ? 'Malicious' : 'Suspicious';
            status.className = `status-pill status-${isMalicious ? 'danger' : 'warning'}`;
            detail.textContent = `Risk score: ${maxScore}%`;
            card.classList.add(isMalicious ? 'border-danger' : 'border-warning');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = `Risk score: ${maxScore}%`;
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
        if (score >= 40) {
            const isMalicious = score >= 75;
            status.textContent = isMalicious ? 'Malicious' : 'Suspicious';
            status.className = `status-pill status-${isMalicious ? 'danger' : 'warning'}`;
            detail.textContent = `Confidence: ${score}% (${ab.total_reports || 0} reports)`;
            card.classList.add(isMalicious ? 'border-danger' : 'border-warning');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = `Confidence: ${score}%`;
        }
    }

    function populateEnginePhishTank(pt, isHit) {
        const status = document.getElementById('engine-phishtank-status');
        const detail = document.getElementById('engine-phishtank-detail');
        const card = document.getElementById('card-phishtank');
        card.className = 'engine-card';
        if (pt && pt.error_message) {
            handleEngineError(card, status, detail, pt);
            return;
        }
        if (isHit && pt && pt.in_database) {
            status.textContent = 'Malicious';
            status.className = 'status-pill status-danger';
            detail.textContent = 'Listed in PhishTank database';
            card.classList.add('border-danger');
        } else {
            status.textContent = 'Clean';
            status.className = 'status-pill status-clean';
            detail.textContent = 'No listing found';
        }
    }
});
