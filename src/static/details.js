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

    function handleEngineError(metricEl, verdictEl, dataObj) {
        verdictEl.textContent = '● Error';
        verdictEl.style.color = '#ef4444';
        metricEl.textContent = dataObj?.error_message || 'Lookup failed';
    }

    function populateEngineVT(vt, isHit) {
        const metric = document.getElementById('threat-vt-metric');
        const verdict = document.getElementById('threat-vt-verdict');
        if (vt && vt.error_message) {
            handleEngineError(metric, verdict, vt);
            return;
        }
        if (isHit && vt && vt.malicious > 0) {
            verdict.textContent = '● Malicious';
            verdict.style.color = '#ef4444';
            metric.textContent = `${vt.malicious} / ${vt.total_engines || 92} detections`;
        } else {
            verdict.textContent = '● Clean';
            verdict.style.color = '#10b981';
            metric.textContent = `0 / ${vt ? vt.total_engines || 92 : 92} detections`;
        }
    }

    function populateEngineGSB(gsb, isHit) {
        const metric = document.getElementById('threat-gsb-metric');
        const verdict = document.getElementById('threat-gsb-verdict');
        if (gsb && gsb.error_message) {
            handleEngineError(metric, verdict, gsb);
            return;
        }
        if (isHit && gsb && gsb.threat_found) {
            verdict.textContent = '● Dangerous';
            verdict.style.color = '#ef4444';
            metric.textContent = `Threat type: ${gsb.threat_type || 'Malware'}`;
        } else {
            verdict.textContent = '● Safe';
            verdict.style.color = '#10b981';
            metric.textContent = 'Clean';
        }
    }

    function populateEngineURLHaus(uh, isHit) {
        const metric = document.getElementById('threat-urlhaus-metric');
        const verdict = document.getElementById('threat-urlhaus-verdict');
        if (uh && uh.error_message) {
            handleEngineError(metric, verdict, uh);
            return;
        }
        if (isHit && uh && uh.query_status === 'ok') {
            verdict.textContent = '● Malicious';
            verdict.style.color = '#ef4444';
            metric.textContent = `Malicious: ${uh.threat || 'malware'}`;
        } else {
            verdict.textContent = '● Clean';
            verdict.style.color = '#10b981';
            metric.textContent = 'Not blacklisted';
        }
    }

    function populateEngineURLScan(us, isHit) {
        const metric = document.getElementById('threat-urlscan-metric');
        const verdict = document.getElementById('threat-urlscan-verdict');
        if (us && us.error_message) {
            handleEngineError(metric, verdict, us);
            return;
        }
        const globalScore = us ? us.malicious_score || 0 : 0;
        const localScore = us ? Math.round((us.final_local_score || 0) * 100) : 0;
        const formScore = us ? Math.round((us.form_risk_score || 0) * 100) : 0;
        const maxScore = Math.max(globalScore, localScore, formScore);

        metric.textContent = `${maxScore} / 100 malicious verdicts`;
        
        if (isHit || maxScore >= 40) {
            const isMalicious = maxScore >= 75;
            verdict.textContent = isMalicious ? '● Malicious' : '● Suspicious';
            verdict.style.color = isMalicious ? '#ef4444' : '#f59e0b';
        } else {
            verdict.textContent = '● Safe (Cached Scan)';
            verdict.style.color = '#10b981';
        }
    }

    function populateEngineAbuseIPDB(ab, isHit) {
        const metric = document.getElementById('threat-abuseipdb-metric');
        const verdict = document.getElementById('threat-abuseipdb-verdict');
        if (ab && ab.error_message) {
            handleEngineError(metric, verdict, ab);
            return;
        }
        const score = ab ? ab.abuse_score || 0 : 0;
        metric.textContent = ab && ab.ip_address ? ab.ip_address : '-';
        
        if (score >= 40) {
            const isMalicious = score >= 75;
            verdict.textContent = isMalicious ? `● Malicious (${score}% abuse)` : `● Suspicious (${score}% abuse)`;
            verdict.style.color = isMalicious ? '#ef4444' : '#f59e0b';
        } else {
            verdict.textContent = `● Trustworthy (${score}% abuse)`;
            verdict.style.color = '#10b981';
        }
    }

    function populateEnginePhishTank(pt, isHit) {
        const metric = document.getElementById('threat-phishtank-metric');
        const verdict = document.getElementById('threat-phishtank-verdict');
        if (pt && pt.error_message) {
            handleEngineError(metric, verdict, pt);
            return;
        }
        if (isHit && pt && pt.in_database) {
            verdict.textContent = '● Malicious';
            verdict.style.color = '#ef4444';
            metric.textContent = 'Listed in PhishTank database';
        } else {
            verdict.textContent = '● Clean';
            verdict.style.color = '#10b981';
            metric.textContent = 'No match found';
        }
    }

    // --- SCREENSHOT MODAL ZOOM EVENT HANDLERS ---
    const screenshotImg = document.getElementById('dynamic-screenshot-img');
    const modal = document.getElementById('screenshot-modal');
    const modalImg = document.getElementById('modal-img');
    const closeModal = document.getElementById('close-modal');

    if (screenshotImg && modal && modalImg) {
        screenshotImg.style.cursor = 'zoom-in';
        screenshotImg.addEventListener('click', () => {
            modalImg.src = screenshotImg.src;
            modal.style.display = 'flex';
        });

        if (closeModal) {
            closeModal.addEventListener('click', () => {
                modal.style.display = 'none';
            });
        }

        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target === modalImg) {
                modal.style.display = 'none';
            }
        });
    }
});
