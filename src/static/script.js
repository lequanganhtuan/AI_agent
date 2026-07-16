document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyze-form');
    const input = document.getElementById('url-input');
    const btnText = document.querySelector('.btn-text');
    const spinner = document.getElementById('spinner');
    const errorMsg = document.getElementById('error-message');
    
    // Summary elements
    const summarySection = document.getElementById('summary-section');
    const summaryCard = document.getElementById('summary-card');
    const summaryScorePath = document.getElementById('summary-score-path');
    const summaryScoreValue = document.getElementById('summary-score-value');
    const summaryVerdict = document.getElementById('summary-verdict');
    const summaryConfidence = document.getElementById('summary-confidence');
    const summaryInsightText = document.getElementById('summary-insight-text');

    // Restore last analyzed scan state on page load
    const recentScanId = localStorage.getItem('recent_scan_id');
    if (recentScanId) {
        loadRecentScan(recentScanId);
    }

    async function loadRecentScan(scanId) {
        try {
            const response = await fetch(`/api/history/${scanId}`);
            if (response.ok) {
                const data = await response.json();
                input.value = data.url || data.validation.normalized_url;
                displayResults(data);
            }
        } catch (err) {
            console.warn("Failed to load recent scan from local storage fallback:", err);
        }
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

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = input.value.trim();
        if (!url) return;

        // Reset UI
        errorMsg.classList.add('hidden');
        if (summarySection) summarySection.classList.add('hidden');
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
        const ai = data.ai || {};
        const risk = ai.risk || {};
        const content = ai.content || {};
        
        const threatRisk = data.threat_intel?.risk || data.threat_intelligence?.risk || data.static?.risk;

        // Unified composite score from backend
        const score = typeof data.score === 'number'
            ? Math.round(data.score)
            : (typeof risk.score === 'number' ? Math.round(risk.score) : (threatRisk && typeof threatRisk.score === 'number' ? Math.round(threatRisk.score) : 0));

        const verdict = data.verdict 
            || content.recommended_action 
            || (threatRisk && threatRisk.verdict) 
            || (score >= 70 ? 'BLOCK' : score >= 40 ? 'WARN' : 'ALLOW');

        const rawConf = content.confidence;
        const confidence = typeof rawConf === 'number' 
            ? `${Math.round(rawConf * 100)}%` 
            : (threatRisk && typeof threatRisk.confidence === 'number' ? `${Math.round(threatRisk.confidence * 100)}%` : '100%');

        const insight = content.summary 
            || content.website_purpose 
            || (threatRisk && threatRisk.summary) 
            || 'No AI content audit telemetry collected.';

        // Animate gauge
        setTimeout(() => {
            summaryScorePath.setAttribute('stroke-dasharray', `${score}, 100`);
            animateValue(summaryScoreValue, 0, score, 1000);
        }, 100);

        // Update Verdict Badge styling
        summaryVerdict.textContent = verdict;
        summaryVerdict.className = 'summary-value status-pill';
        if (verdict === 'BLOCK') {
            summaryVerdict.style.background = 'rgba(239, 68, 68, 0.15)';
            summaryVerdict.style.color = '#ef4444';
            summaryVerdict.style.border = '1px solid rgba(239, 68, 68, 0.3)';
        } else if (verdict === 'WARN') {
            summaryVerdict.style.background = 'rgba(245, 158, 11, 0.15)';
            summaryVerdict.style.color = '#f59e0b';
            summaryVerdict.style.border = '1px solid rgba(245, 158, 11, 0.3)';
        } else if (verdict === 'MONITOR') {
            summaryVerdict.style.background = 'rgba(59, 130, 246, 0.15)';
            summaryVerdict.style.color = '#3b82f6';
            summaryVerdict.style.border = '1px solid rgba(59, 130, 246, 0.3)';
        } else if (verdict === 'SUSPICIOUS') {
            summaryVerdict.style.background = 'rgba(245, 158, 11, 0.15)';
            summaryVerdict.style.color = '#f59e0b';
            summaryVerdict.style.border = '1px solid rgba(245, 158, 11, 0.3)';
        } else {
            summaryVerdict.style.background = 'rgba(16, 185, 129, 0.15)';
            summaryVerdict.style.color = '#10b981';
            summaryVerdict.style.border = '1px solid rgba(16, 185, 129, 0.3)';
        }

        summaryConfidence.textContent = confidence;
        summaryInsightText.textContent = insight;

        // Update screenshot on summary card
        const summaryScreenshotContainer = document.getElementById('summary-screenshot-container');
        const summaryScreenshotImg = document.getElementById('summary-screenshot-img');
        if (summaryScreenshotContainer && summaryScreenshotImg) {
            const screenshotPath = (data.dynamic && data.dynamic.screenshot_path) ? data.dynamic.screenshot_path : null;
            if (screenshotPath) {
                summaryScreenshotImg.src = '/' + screenshotPath;
                summaryScreenshotContainer.classList.remove('hidden');
            } else {
                summaryScreenshotContainer.classList.add('hidden');
            }
        }

        // Save last analyzed scan ID to local storage
        localStorage.setItem('recent_scan_id', data.id);

        // Redirect on click
        summaryCard.onclick = () => {
            window.location.href = `/details?id=${data.id}`;
        };

        // Show section
        summarySection.classList.remove('hidden');
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

    async function fetchHistory(search = '', verdict = 'ALL') {
        historyLoading.classList.remove('hidden');
        historyEmpty.classList.add('hidden');
        historyItemsContainer.innerHTML = '';

        try {
            let url = `/api/history?limit=30`;
            if (search) {
                url += `&search=${encodeURIComponent(search)}`;
            }
            if (verdict && verdict !== 'ALL') {
                url += `&verdict=${encodeURIComponent(verdict)}`;
            }

            const response = await fetch(url);
            if (!response.ok) throw new Error('Failed to fetch scan history');

            const scans = await response.json();
            renderScansList(scans);
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

            const formattedTime = formatTimeAgo(new Date(scan.timestamp));
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

            // When clicking a history item, redirect straight to its details page
            card.addEventListener('click', () => {
                closeHistoryDrawer();
                window.location.href = `/details?id=${scan.id}`;
            });
            historyItemsContainer.appendChild(card);
        });
    }

    let searchTimeout = null;
    function applyFilters() {
        if (searchTimeout) {
            clearTimeout(searchTimeout);
        }
        searchTimeout = setTimeout(() => {
            const query = historySearch.value.trim();
            const selectedVerdict = historyFilter.value;
            fetchHistory(query, selectedVerdict);
        }, 300);
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
