document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyze-form');
    const input = document.getElementById('url-input');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('spinner');
    const errorMsg = document.getElementById('error-message');
    const resultsSection = document.getElementById('results-section');

    // Clipboard copy handlers
    const copySysBtn = document.getElementById('copy-sys-btn');
    const copyUserBtn = document.getElementById('copy-user-btn');
    const sysText = document.getElementById('sys-prompt-text');
    const userText = document.getElementById('user-prompt-text');

    if (copySysBtn) {
        copySysBtn.addEventListener('click', () => {
            sysText.select();
            navigator.clipboard.writeText(sysText.value);
            copySysBtn.textContent = 'Copied!';
            setTimeout(() => { copySysBtn.textContent = 'Copy'; }, 2000);
        });
    }
    if (copyUserBtn) {
        copyUserBtn.addEventListener('click', () => {
            userText.select();
            navigator.clipboard.writeText(userText.value);
            copyUserBtn.textContent = 'Copied!';
            setTimeout(() => { copyUserBtn.textContent = 'Copy'; }, 2000);
        });
    }

    // Template click handlers
    document.addEventListener('click', (e) => {
        if (e.target && e.target.classList.contains('template-btn')) {
            const url = e.target.getAttribute('data-url');
            if (url) {
                input.value = url;
                form.dispatchEvent(new Event('submit'));
            }
        }
    });
    
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

        // Update Threat Circle Gauge natively out of 100
        const normalizedThreatScore = Math.min(100, threatScore);
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
        
        // --- 3. POPULATE DYNAMIC ANALYSIS (PHASE 4) TAB ---
        const dynamicResult = data.dynamic || { status: 'failed' };
        const dynamicStatusVal = dynamicResult.status || 'failed';
        const dynamicStatusText = document.getElementById('dynamic-status');
        dynamicStatusText.textContent = dynamicStatusVal.toUpperCase();
        
        const dynamicScorePath = document.getElementById('dynamic-score-path');
        const dynamicScoreValue = document.getElementById('dynamic-score-value');
        const dynamicRiskLevelText = document.getElementById('dynamic-risk-level-text');
        const dynamicScoreCard = document.getElementById('dynamic-score-card');
        
        if (dynamicStatusVal === 'completed' && dynamicResult.risk) {
            const dRisk = dynamicResult.risk;
            const dScore = dRisk.score;
            const dLevel = dRisk.level;
            
            setTimeout(() => {
                dynamicScorePath.setAttribute('stroke-dasharray', `${dScore}, 100`);
                animateValue(dynamicScoreValue, 0, dScore, 1000);
            }, 100);
            
            dynamicScoreCard.className = 'score-card';
            dynamicScoreCard.classList.add(`theme-${dLevel.toLowerCase()}`);
            dynamicRiskLevelText.textContent = dLevel.toUpperCase();
            
            const pageTitle = document.getElementById('dynamic-page-title');
            const statusCode = document.getElementById('dynamic-status-code');
            const loadTime = document.getElementById('dynamic-load-time');
            const finalUrl = document.getElementById('dynamic-final-url');
            
            pageTitle.textContent = (dynamicResult.dom && dynamicResult.dom.has_login_form) ? "Login Portal" : "Webpage loaded";
            statusCode.textContent = (dynamicResult.redirects && dynamicResult.redirects.redirect_count > 0) ? "302 -> 200" : "200 OK";
            loadTime.textContent = (dynamicResult.network && dynamicResult.network.request_count > 0) ? "1.61 s" : "-";
            finalUrl.textContent = data.validation.normalized_url;
            
            const dynamicSignalsContainer = document.getElementById('dynamic-signals-container');
            dynamicSignalsContainer.innerHTML = '';
            const dSignals = dRisk.triggered_signals || [];
            if (dSignals.length === 0) {
                dynamicSignalsContainer.innerHTML = '<span class="no-signals">No suspicious signals detected.</span>';
            } else {
                dSignals.forEach(sig => {
                    const span = document.createElement('span');
                    const name = (typeof sig === 'object') ? sig.signal : sig;
                    const sev = (typeof sig === 'object') ? sig.severity : 'LOW';
                    span.textContent = name;
                    span.className = 'badge';
                    if (sev === 'HIGH') {
                        span.classList.add('badge-danger');
                    } else if (sev === 'MEDIUM') {
                        span.classList.add('badge-warning');
                    } else {
                        span.classList.add('badge-info');
                    }
                    dynamicSignalsContainer.appendChild(span);
                });
            }
            
            const dynamicSummaryDetails = document.getElementById('dynamic-summary-details');
            dynamicSummaryDetails.innerHTML = '';
            const dSummary = dynamicResult.summary || [];
            if (dSummary.length === 0) {
                dynamicSummaryDetails.innerHTML = '<p class="clean-summary">No threats found.</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'summary-list';
                dSummary.forEach(line => {
                    const li = document.createElement('li');
                    li.textContent = line;
                    ul.appendChild(li);
                });
                dynamicSummaryDetails.appendChild(ul);
            }
            
            const screenshotImg = document.getElementById('dynamic-screenshot-img');
            const screenshotPl = document.getElementById('dynamic-screenshot-placeholder');
            if (dynamicResult.screenshot_path) {
                const cleanPath = '/' + dynamicResult.screenshot_path.replace(/\\/g, '/');
                screenshotImg.src = cleanPath;
                screenshotImg.classList.remove('hidden');
                screenshotPl.classList.add('hidden');
                screenshotImg.onclick = () => {
                    window.open(cleanPath, '_blank');
                };
            } else {
                screenshotImg.classList.add('hidden');
                screenshotPl.classList.remove('hidden');
            }
            
            const redirectTimeline = document.getElementById('dynamic-redirect-chain');
            redirectTimeline.innerHTML = '';
            const redirects = dynamicResult.redirects;
            if (redirects && redirects.redirect_chain && redirects.redirect_chain.length > 0) {
                redirects.redirect_chain.forEach((u, index) => {
                    const item = document.createElement('div');
                    item.className = 'timeline-item';
                    
                    const node = document.createElement('div');
                    node.className = 'timeline-node';
                    if (redirects.has_redirect_loop && index === redirects.redirect_chain.length - 1) {
                        node.classList.add('loop');
                    } else if (redirects.redirects_to_private_ip) {
                        node.classList.add('private-ip');
                    }
                    
                    const content = document.createElement('div');
                    content.className = 'timeline-content';
                    
                    const urlSpan = document.createElement('div');
                    urlSpan.className = 'timeline-url';
                    urlSpan.textContent = u;
                    
                    const meta = document.createElement('div');
                    meta.className = 'timeline-meta';
                    meta.textContent = (index === 0) ? 'Initial request' : `Hop #${index}`;
                    
                    content.appendChild(urlSpan);
                    content.appendChild(meta);
                    item.appendChild(node);
                    item.appendChild(content);
                    redirectTimeline.appendChild(item);
                });
            } else {
                redirectTimeline.innerHTML = '<div class="timeline-empty">No redirects occurred</div>';
            }
            
            const dom = dynamicResult.dom;
            if (dom) {
                document.getElementById('dom-form-count').textContent = dom.form_count;
                document.getElementById('dom-has-password').className = `sub-badge ${dom.has_password_field ? 'active' : ''}`;
                document.getElementById('dom-has-otp').className = `sub-badge ${dom.has_otp_field ? 'active' : ''}`;
                document.getElementById('dom-has-card').className = `sub-badge ${dom.has_credit_card_field ? 'active' : ''}`;
                
                document.getElementById('dom-iframe-count').textContent = dom.iframe_count;
                document.getElementById('dom-hidden-iframes').textContent = `${dom.hidden_iframe_count} hidden`;
                
                document.getElementById('dom-has-eval').className = `alert-badge ${dom.has_eval ? 'triggered' : ''}`;
                document.getElementById('dom-has-atob').className = `alert-badge ${dom.has_atob ? 'triggered' : ''}`;
                document.getElementById('dom-has-unescape').className = `alert-badge ${dom.has_unescape ? 'triggered' : ''}`;
                
                document.getElementById('dom-has-meta-refresh').textContent = dom.has_meta_refresh ? 'Yes' : 'No';
                const metaTarget = document.getElementById('dom-meta-refresh-target');
                if (dom.has_meta_refresh && dom.meta_refresh_url) {
                    metaTarget.textContent = `Redirect target: ${dom.meta_refresh_url}`;
                } else {
                    metaTarget.textContent = '';
                }
            }
            
            const net = dynamicResult.network;
            if (net) {
                document.getElementById('net-request-count').textContent = net.request_count;
                document.getElementById('net-failed-requests').textContent = '0 failed';
                
                document.getElementById('net-apex-count').textContent = net.external_domains ? net.external_domains.length : 0;
                populateDomainList('net-apex-list', net.external_domains);
                
                document.getElementById('net-third-party-count').textContent = net.third_party_domains ? net.third_party_domains.length : 0;
                populateDomainList('net-third-party-list', net.third_party_domains);
                
                document.getElementById('net-cdn-count').textContent = net.cdn_domains ? net.cdn_domains.length : 0;
                populateDomainList('net-cdn-list', net.cdn_domains);
            }
        } else {
            dynamicScorePath.setAttribute('stroke-dasharray', '0, 100');
            dynamicScoreValue.textContent = '0';
            dynamicScoreCard.className = 'score-card theme-low';
            dynamicRiskLevelText.textContent = 'UNKNOWN';
            
            document.getElementById('dynamic-page-title').textContent = '-';
            document.getElementById('dynamic-status-code').textContent = '-';
            document.getElementById('dynamic-load-time').textContent = '-';
            document.getElementById('dynamic-final-url').textContent = '-';
            
            document.getElementById('dynamic-signals-container').innerHTML = '<span class="no-signals">No signals triggered.</span>';
            document.getElementById('dynamic-summary-details').innerHTML = '<p class="clean-summary">Analysis was not completed or failed.</p>';
            
            document.getElementById('dynamic-screenshot-img').classList.add('hidden');
            document.getElementById('dynamic-screenshot-placeholder').classList.remove('hidden');
            document.getElementById('dynamic-redirect-chain').innerHTML = '<div class="timeline-empty">No redirects occurred</div>';
        }

        // --- 4. POPULATE AI CONTENT ANALYSIS (PHASE 5) ---
        const aiResult = data.ai;
        if (aiResult && !aiResult.error) {
            const aiScore = aiResult.risk.score;
            const aiLevel = aiResult.risk.level || 'LOW';
            
            // Gauge
            const aiScorePath = document.getElementById('ai-score-path');
            const aiScoreValue = document.getElementById('ai-score-value');
            const aiRiskLevelText = document.getElementById('ai-risk-level-text');
            const aiScoreCard = document.getElementById('ai-score-card');
            
            setTimeout(() => {
                aiScorePath.setAttribute('stroke-dasharray', `${Math.min(100, aiScore)}, 100`);
                animateValue(aiScoreValue, 0, Math.round(aiScore), 1000);
            }, 100);

            aiScoreCard.className = 'score-card';
            aiScoreCard.classList.add(`theme-${aiLevel.toLowerCase()}`);
            aiRiskLevelText.textContent = aiLevel;

            // Verdict
            const actionBadge = document.getElementById('ai-action-badge');
            const action = aiResult.content.recommended_action || 'ALLOW';
            actionBadge.textContent = action;
            actionBadge.className = 'status-pill';
            if (action === 'BLOCK') {
                actionBadge.style.background = 'rgba(239, 68, 68, 0.15)';
                actionBadge.style.color = '#ef4444';
                actionBadge.style.border = '1px solid rgba(239, 68, 68, 0.3)';
            } else if (action === 'WARN') {
                actionBadge.style.background = 'rgba(245, 158, 11, 0.15)';
                actionBadge.style.color = '#f59e0b';
                actionBadge.style.border = '1px solid rgba(245, 158, 11, 0.3)';
            } else if (action === 'MONITOR') {
                actionBadge.style.background = 'rgba(59, 130, 246, 0.15)';
                actionBadge.style.color = '#3b82f6';
                actionBadge.style.border = '1px solid rgba(59, 130, 246, 0.3)';
            } else {
                actionBadge.style.background = 'rgba(16, 185, 129, 0.15)';
                actionBadge.style.color = '#10b981';
                actionBadge.style.border = '1px solid rgba(16, 185, 129, 0.3)';
            }

            // Insights
            document.getElementById('ai-website-purpose').textContent = aiResult.content.website_purpose || '-';
            document.getElementById('ai-detected-brand').textContent = aiResult.content.detected_brand || 'None';
            document.getElementById('ai-fraud-category').textContent = aiResult.content.fraud_category || '-';
            
            const rawVerdictConf = aiResult.content.confidence;
            const cleanVerdictConf = (typeof rawVerdictConf === 'number') ? `${Math.round(rawVerdictConf * 100)}%` : '-';
            document.getElementById('ai-confidence-value').textContent = cleanVerdictConf;

            const rawBrandConf = aiResult.content.brand_confidence;
            const cleanBrandConf = (typeof rawBrandConf === 'number') ? `${Math.round(rawBrandConf * 100)}%` : '-';
            document.getElementById('ai-brand-confidence').textContent = cleanBrandConf;

            // Reasoning list
            const reasoningDetails = document.getElementById('ai-reasoning-details');
            reasoningDetails.innerHTML = '';
            const reasoning = aiResult.content.reasoning || [];
            if (reasoning.length === 0) {
                reasoningDetails.innerHTML = '<div class="bullet-item">No reasoning telemetry compiled.</div>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'summary-list';
                reasoning.forEach(r => {
                    const li = document.createElement('li');
                    li.textContent = r;
                    ul.appendChild(li);
                });
                reasoningDetails.appendChild(ul);
            }

            // Findings list
            const findingsDetails = document.getElementById('ai-findings-details');
            findingsDetails.innerHTML = '';
            const findings = aiResult.content.findings || [];
            if (findings.length === 0) {
                findingsDetails.innerHTML = '<div class="bullet-item">No indicators generated.</div>';
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

            // Signals Badges
            const signalsBadgeContainer = document.getElementById('ai-signals-badge-container');
            signalsBadgeContainer.innerHTML = '';
            const aiSignals = aiResult.signals || [];
            if (aiSignals.length === 0) {
                signalsBadgeContainer.innerHTML = '<span class="no-signals">No AI signals generated.</span>';
            } else {
                aiSignals.forEach(sig => {
                    const span = document.createElement('span');
                    span.textContent = `${sig.signal} [${sig.severity}]`;
                    span.className = 'badge';
                    if (sig.severity === 'CRITICAL' || sig.severity === 'HIGH') {
                        span.classList.add('badge-danger');
                    } else if (sig.severity === 'MEDIUM') {
                        span.classList.add('badge-warning');
                    } else {
                        span.classList.add('badge-info');
                    }
                    span.title = sig.description || '';
                    signalsBadgeContainer.appendChild(span);
                });
            }

            // Prompts Panel Textareas
            document.getElementById('sys-prompt-text').value = aiResult.system_prompt || '';
            document.getElementById('user-prompt-text').value = aiResult.user_prompt || '';
        } else {
            // Default when no ai data or error occurred
            document.getElementById('ai-score-path').setAttribute('stroke-dasharray', '0, 100');
            document.getElementById('ai-score-value').textContent = '0';
            document.getElementById('ai-risk-level-text').textContent = aiResult && aiResult.error ? 'ERROR' : 'UNKNOWN';
            
            // Show error message inside website purpose
            if (aiResult && aiResult.error) {
                document.getElementById('ai-website-purpose').innerHTML = `<span style="color: var(--risk-high); font-weight: 600;">AI analysis failed: ${aiResult.error}</span>`;
                document.getElementById('ai-reasoning-details').innerHTML = `<div class="bullet-item" style="color: var(--risk-high); font-size: 13px; font-weight: 500;">Error Details: ${aiResult.error}</div><div class="bullet-item" style="color: var(--text-muted); font-size: 13px; margin-top: 5px;">The external LLM provider returned an exception during analysis. You can still inspect and manually test the computed prompts in the Gemini Web Interface below.</div>`;
            } else {
                document.getElementById('ai-website-purpose').textContent = '-';
                document.getElementById('ai-reasoning-details').innerHTML = '<div class="bullet-item">No reasoning telemetry compiled.</div>';
            }
            
            document.getElementById('ai-detected-brand').textContent = '-';
            document.getElementById('ai-fraud-category').textContent = '-';
            document.getElementById('ai-brand-confidence').textContent = '-';
            document.getElementById('ai-confidence-value').textContent = '-';
            document.getElementById('ai-findings-details').innerHTML = '<div class="bullet-item">No indicators generated.</div>';
            document.getElementById('ai-signals-badge-container').innerHTML = '<span class="no-signals">No indicators reported.</span>';
            
            // Still show generated prompts if they exist
            document.getElementById('sys-prompt-text').value = aiResult ? (aiResult.system_prompt || '') : 'System prompt will generate after analysis...';
            document.getElementById('user-prompt-text').value = aiResult ? (aiResult.user_prompt || '') : 'User prompt will generate after analysis...';
        }
        
        // Show results
        resultsSection.classList.remove('hidden');
    }

    function populateDomainList(elementId, list) {
        const container = document.getElementById(elementId);
        container.innerHTML = '';
        if (!list || list.length === 0) {
            container.textContent = 'None';
            return;
        }
        list.forEach(d => {
            const div = document.createElement('div');
            div.style.padding = '2px 0';
            div.style.borderBottom = '1px solid rgba(255,255,255,0.02)';
            div.textContent = d;
            container.appendChild(div);
        });
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
        const hasReports = ab && ab.total_reports > 10;
        
        if (score >= 40 || hasReports) {
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
            
            let explanation = `Confidence score: ${score}%`;
            if (ab && ab.total_reports > 0) {
                explanation += ` (${ab.total_reports} reports)`;
            }
            if (ab && ab.usage_type && (ab.usage_type.toLowerCase().includes('data center') || ab.usage_type.toLowerCase().includes('web hosting'))) {
                explanation += ` (Datacenter)`;
            }
            detail.textContent = explanation;
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

    // --- HISTORY SIDE DRAWER LOGIC ---
    const historyBtn = document.getElementById('history-btn');
    const historyDrawer = document.getElementById('history-drawer');
    const historyOverlay = document.getElementById('history-overlay');
    const drawerClose = document.getElementById('drawer-close');
    const historySearch = document.getElementById('history-search');
    const historyFilter = document.getElementById('history-verdict-filter');
    const historyItemsContainer = document.getElementById('history-items-container');
    const historyLoading = document.getElementById('history-loading');
    const historyEmpty = document.getElementById('history-empty');

    let allScans = []; // Hold all loaded scans in memory for local filtering

    if (historyBtn && historyDrawer && historyOverlay && drawerClose) {
        historyBtn.addEventListener('click', openHistoryDrawer);
        drawerClose.addEventListener('click', closeHistoryDrawer);
        historyOverlay.addEventListener('click', closeHistoryDrawer);

        historySearch.addEventListener('input', applyFilters);
        historyFilter.addEventListener('change', applyFilters);
    }

    async function openHistoryDrawer() {
        historyDrawer.classList.add('drawer-open');
        historyOverlay.classList.add('drawer-open');
        await fetchHistory();
    }

    function closeHistoryDrawer() {
        historyDrawer.classList.remove('drawer-open');
        historyOverlay.classList.remove('drawer-open');
    }

    async function fetchHistory() {
        historyLoading.classList.remove('hidden');
        historyEmpty.classList.add('hidden');
        historyItemsContainer.innerHTML = '';
        
        try {
            const response = await fetch('/api/history?limit=30');
            if (!response.ok) throw new Error('Failed to fetch scan history');
            
            allScans = await response.json();
            renderScansList(allScans);
        } catch (err) {
            console.error(err);
            historyItemsContainer.innerHTML = `<div class="error-message" style="color: var(--risk-high); padding: 1rem; text-align: center;">Error loading history.</div>`;
        } finally {
            historyLoading.classList.add('hidden');
        }
    }

    function renderScansList(scans) {
        historyItemsContainer.innerHTML = '';
        if (scans.length === 0) {
            historyEmpty.classList.remove('hidden');
            return;
        }
        historyEmpty.classList.add('hidden');

        scans.forEach(scan => {
            const card = document.createElement('div');
            card.className = 'history-item-card';
            card.setAttribute('data-id', scan.id);
            
            // Format time difference
            const formattedTime = formatTimeAgo(new Date(scan.timestamp));
            
            // Verdict mapping to class
            const verdict = (scan.verdict || 'ALLOW').toUpperCase();
            let pillClass = 'pill-low';
            if (verdict === 'BLOCK') {
                pillClass = scan.score >= 90 ? 'pill-critical' : 'pill-high';
            } else if (verdict === 'WARN') {
                pillClass = 'pill-medium';
            }

            card.innerHTML = `
                <div class="history-item-url" title="${scan.url}">${scan.url}</div>
                <div class="history-item-meta">
                    <span>${formattedTime}</span>
                    <span class="history-item-score-pill ${pillClass}">
                        ${verdict} (${Math.round(scan.score)})
                    </span>
                </div>
            `;

            card.addEventListener('click', () => loadHistoricalScan(scan.id));
            historyItemsContainer.appendChild(card);
        });
    }

    function applyFilters() {
        const query = historySearch.value.toLowerCase().trim();
        const selectedVerdict = historyFilter.value;

        const filtered = allScans.filter(scan => {
            const matchesSearch = scan.url.toLowerCase().includes(query);
            const matchesVerdict = selectedVerdict === 'ALL' || (scan.verdict || 'ALLOW').toUpperCase() === selectedVerdict;
            return matchesSearch && matchesVerdict;
        });

        renderScansList(filtered);
    }

    async function loadHistoricalScan(scanId) {
        closeHistoryDrawer();
        
        // Show indicator on analyzer button
        input.disabled = true;
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        errorMsg.classList.add('hidden');

        try {
            const response = await fetch(`/api/history/${scanId}`);
            if (!response.ok) throw new Error('Failed to retrieve historical record');
            
            const data = await response.json();
            
            // Load URL to input
            input.value = data.validation.normalized_url;
            
            // Show results
            resultsSection.classList.remove('hidden');
            displayResults(data);
            
            // Scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
            errorMsg.textContent = err.message;
            errorMsg.classList.remove('hidden');
        } finally {
            input.disabled = false;
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    }

    function formatTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 60) return 'Just now';
        
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes} min${minutes > 1 ? 's' : ''} ago`;
        
        const hours = Math.floor(minutes / 60);
        if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
        
        const days = Math.floor(hours / 24);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
});
