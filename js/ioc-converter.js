/**
 * ioc-converter.js
 * IOC → Sigma Rule Converter
 * Detects IOC types, disambiguates uncertain entries, and generates Sigma YAML.
 */
'use strict';

const IocConverter = (() => {

    // ── IOC type definitions ────────────────────────────────────────────
    const TYPES = {
        ipv4:      { label: 'IPv4 Address',    icon: 'bi-hdd-network',       color: '#ff6b6b', sigmaField: 'DestinationIp',   modifier: null,       logsource: { product: 'windows', category: 'network_connection' } },
        ipv6:      { label: 'IPv6 Address',    icon: 'bi-hdd-network',       color: '#ff8787', sigmaField: 'DestinationIp',   modifier: null,       logsource: { product: 'windows', category: 'network_connection' } },
        domain:    { label: 'Domain / FQDN',   icon: 'bi-globe',             color: '#74c0fc', sigmaField: 'QueryName',        modifier: 'contains', logsource: { product: 'windows', category: 'dns_query' } },
        url:       { label: 'URL',             icon: 'bi-link-45deg',        color: '#4dabf7', sigmaField: 'cs-uri',           modifier: 'contains', logsource: { category: 'webserver' } },
        md5:       { label: 'MD5 Hash',        icon: 'bi-fingerprint',       color: '#ffa94d', sigmaField: 'md5',              modifier: null,       logsource: { product: 'windows', category: 'process_creation' } },
        sha1:      { label: 'SHA1 Hash',       icon: 'bi-fingerprint',       color: '#ffc078', sigmaField: 'sha1',             modifier: null,       logsource: { product: 'windows', category: 'process_creation' } },
        sha256:    { label: 'SHA256 Hash',     icon: 'bi-fingerprint',       color: '#ffd8a8', sigmaField: 'sha256',           modifier: null,       logsource: { product: 'windows', category: 'process_creation' } },
        filepath:  { label: 'File Path',       icon: 'bi-folder2-open',      color: '#a9e34b', sigmaField: 'Image',            modifier: 'contains', logsource: { product: 'windows', category: 'process_creation' } },
        filename:  { label: 'File Name',       icon: 'bi-file-earmark-code', color: '#c0eb75', sigmaField: 'Image',            modifier: 'endswith', logsource: { product: 'windows', category: 'process_creation' } },
        cmdline:   { label: 'Command Line',    icon: 'bi-terminal',          color: '#b197fc', sigmaField: 'CommandLine',      modifier: 'contains', logsource: { product: 'windows', category: 'process_creation' } },
        registry:  { label: 'Registry Key',    icon: 'bi-sliders',           color: '#e599f7', sigmaField: 'TargetObject',     modifier: 'contains', logsource: { product: 'windows', category: 'registry_event' } },
        email:     { label: 'Email Address',   icon: 'bi-envelope',          color: '#63e6be', sigmaField: 'SenderAddress',    modifier: null,       logsource: { category: 'email' } },
        useragent: { label: 'User Agent',      icon: 'bi-browser-chrome',    color: '#94d82d', sigmaField: 'cs-User-Agent',    modifier: 'contains', logsource: { category: 'webserver' } },
        unknown:   { label: 'Unknown',         icon: 'bi-question-circle',   color: '#868e96', sigmaField: 'CommandLine',      modifier: 'contains', logsource: { product: 'windows', category: 'process_creation' } },
    };

    // Maps prefix aliases to canonical type (null = auto-detect within category)
    const PREFIX_MAP = {
        ipv4: 'ipv4', ip4: 'ipv4', ip: null,
        ipv6: 'ipv6', ip6: 'ipv6',
        domain: 'domain', fqdn: 'domain', hostname: 'domain', host: 'domain',
        url: 'url', uri: 'url',
        md5: 'md5',
        sha1: 'sha1',
        sha256: 'sha256', sha2: 'sha256',
        hash: null,
        filepath: 'filepath', path: 'filepath',
        filename: 'filename', file: 'filename',
        cmdline: 'cmdline', commandline: 'cmdline', cmd: 'cmdline', command: 'cmdline',
        registry: 'registry', reg: 'registry', regkey: 'registry',
        email: 'email', mail: 'email',
        useragent: 'useragent', ua: 'useragent',
    };

    // ── Detection engine ────────────────────────────────────────────────

    /**
     * Detect IOC type from a plain value string.
     * Returns { type, confidence (0–1), alternatives[] }
     */
    function detectType(v) {
        if (!v || !v.trim()) return { type: null, confidence: 0, alternatives: [] };
        v = v.trim();

        // IPv4 (with optional CIDR)
        if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v)) {
            const octets = v.split('/')[0].split('.').map(Number);
            if (octets.every(o => o >= 0 && o <= 255))
                return { type: 'ipv4', confidence: 1, alternatives: [] };
        }

        // IPv6
        if (/^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/.test(v) && v.includes(':'))
            return { type: 'ipv6', confidence: 1, alternatives: [] };

        // URL (has scheme)
        if (/^https?:\/\//i.test(v))
            return { type: 'url', confidence: 1, alternatives: [] };

        // Email
        if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v))
            return { type: 'email', confidence: 1, alternatives: [] };

        // Registry key
        if (/^(HK(LM|CU|CR|U|CC|PD)|HKEY_)/i.test(v))
            return { type: 'registry', confidence: 1, alternatives: [] };

        // SHA256 (64 hex chars)
        if (/^[0-9a-fA-F]{64}$/.test(v))
            return { type: 'sha256', confidence: 1, alternatives: [] };

        // SHA1 (40 hex chars)
        if (/^[0-9a-fA-F]{40}$/.test(v))
            return { type: 'sha1', confidence: 1, alternatives: [] };

        // MD5 (32 hex chars) — could also be a very short filename w/o extension; treat as hash
        if (/^[0-9a-fA-F]{32}$/.test(v))
            return { type: 'md5', confidence: 0.95, alternatives: ['filename'] };

        // Windows absolute path
        if (/^[a-zA-Z]:[\\\/]|^\\\\[^\\]+\\/.test(v))
            return { type: 'filepath', confidence: 1, alternatives: [] };

        // Unix absolute path
        if (/^\/[^\s]+\/[^\s]/.test(v))
            return { type: 'filepath', confidence: 0.9, alternatives: ['cmdline'] };

        // User agent heuristics
        if (/Mozilla\/\d+\.\d+|Googlebot|curl\/\d|python-requests|libwww/i.test(v))
            return { type: 'useragent', confidence: 1, alternatives: [] };

        // FQDN / domain
        const isFqdn = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v);
        const hasNoSlash = !/[\/\\]/.test(v);
        const hasNoSpace = !/\s/.test(v);
        const commonExts = /\.(exe|dll|bat|cmd|ps1|vbs|js|msi|scr|com|pif|jar|sys|drv|reg|inf|cab|iso|lnk|hta|cpl|ocx|asp|php|jsp)$/i;

        if (isFqdn) {
            if (commonExts.test(v) && hasNoSlash)
                // Looks like it could be "evil.exe" OR a domain
                return { type: 'filename', confidence: 0.55, alternatives: ['domain', 'cmdline'] };
            return { type: 'domain', confidence: 0.9, alternatives: [] };
        }

        // Filename (has extension, no path separators or spaces)
        if (/\.[a-zA-Z0-9]{1,10}$/.test(v) && hasNoSlash && hasNoSpace)
            return { type: 'filename', confidence: 0.75, alternatives: ['domain', 'cmdline'] };

        // Command line (spaces, shell operators, or common process names)
        if (/\s/.test(v) || /[<>|&;`]/.test(v))
            return { type: 'cmdline', confidence: 0.85, alternatives: ['filepath'] };

        if (/^(powershell|cmd\.exe|wscript|cscript|regsvr32|mshta|rundll32|certutil|bitsadmin|whoami|net |ipconfig|systeminfo|schtasks|reg\.exe|wmic)\b/i.test(v))
            return { type: 'cmdline', confidence: 0.95, alternatives: [] };

        // Path-like without drive letter
        if (/[\/\\]/.test(v))
            return { type: 'filepath', confidence: 0.7, alternatives: ['cmdline'] };

        // Fallback: ask user
        return { type: null, confidence: 0, alternatives: ['ipv4', 'domain', 'filename', 'cmdline', 'cmdline'] };
    }

    // ── Line / CSV parser ───────────────────────────────────────────────

    function parseLine(raw) {
        const line = raw.trim();
        if (!line || line.startsWith('#') || line.startsWith('//')) return null;

        // Check for prefix annotation: word=value
        const prefixMatch = line.match(/^([a-zA-Z0-9_]+)=(.+)$/);
        if (prefixMatch) {
            const key = prefixMatch[1].toLowerCase();
            const val = prefixMatch[2].trim();
            if (key in PREFIX_MAP) {
                let type = PREFIX_MAP[key];
                if (type === null) {
                    // Auto-detect within category
                    if (key === 'ip' || key === 'ip4' || key === 'ip6') {
                        const d = detectType(val);
                        type = (d.type === 'ipv4' || d.type === 'ipv6') ? d.type : 'ipv4';
                    } else if (key === 'hash') {
                        if (/^[0-9a-fA-F]{64}$/.test(val))      type = 'sha256';
                        else if (/^[0-9a-fA-F]{40}$/.test(val)) type = 'sha1';
                        else if (/^[0-9a-fA-F]{32}$/.test(val)) type = 'md5';
                        else type = 'sha256';
                    } else {
                        type = 'cmdline'; // safe fallback
                    }
                }
                return { raw: line, value: val, type, prefixed: true, prefixKey: key, confidence: 1, alternatives: [], needsConfirm: false };
            }
        }

        // Auto-detect
        const { type, confidence, alternatives } = detectType(line);
        const resolvedType = type || (alternatives[0] || 'unknown');
        const needsConfirm = confidence < 0.8 || (alternatives.length > 0 && confidence < 0.9);
        return {
            raw: line,
            value: line,
            type: resolvedType,
            prefixed: false,
            confidence,
            alternatives: alternatives.filter(a => a !== resolvedType),
            needsConfirm,
        };
    }

    function parseText(text) {
        return text.split(/\r?\n/)
            .map(parseLine)
            .filter(Boolean);
    }

    function parseCSV(text) {
        const results = [];
        const lines = text.split(/\r?\n/);
        let headerSkipped = false;

        for (const line of lines) {
            if (!line.trim()) continue;

            // Split CSV respecting quoted values
            const cols = splitCSVLine(line);

            if (cols.length >= 2) {
                const col0 = cols[0].trim().toLowerCase();
                const col1 = cols[1].trim();

                // Header row detection
                if (!headerSkipped && /^(type|indicator_type|ioc_type|kind|category)$/i.test(col0)) {
                    headerSkipped = true;
                    continue;
                }

                // type, value format
                if (col0 in PREFIX_MAP) {
                    const entry = parseLine(`${col0}=${col1}`);
                    if (entry) { results.push(entry); continue; }
                }

                // value, type format (reversed)
                const col1L = col1.toLowerCase();
                if (col1L in PREFIX_MAP) {
                    const entry = parseLine(`${col1L}=${col0}`);
                    if (entry) { results.push(entry); continue; }
                }
            }

            // Fallback: treat whole line as a plain value
            const entry = parseLine(cols[0] || line);
            if (entry) results.push(entry);
        }
        return results;
    }

    function splitCSVLine(line) {
        const result = [];
        let current = '';
        let inQuotes = false;
        for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            if (ch === '"' && (i === 0 || line[i - 1] !== '\\')) {
                inQuotes = !inQuotes;
            } else if (ch === ',' && !inQuotes) {
                result.push(current);
                current = '';
            } else {
                current += ch;
            }
        }
        result.push(current);
        return result.map(s => s.trim().replace(/^"|"$/g, ''));
    }

    function groupByType(entries) {
        const g = {};
        for (const e of entries) {
            const t = e.type || 'unknown';
            if (!g[t]) g[t] = [];
            g[t].push(e);
        }
        return g;
    }

    // ── Sigma YAML generation ───────────────────────────────────────────

    function generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        });
    }

    function escapeYamlStr(s) {
        return String(s).replace(/'/g, "''");
    }

    function generateSigma(groups, opts = {}) {
        const title       = opts.title || 'IOC Detection';
        const description = opts.description || '';
        const level       = opts.level || 'high';

        const typeOrder = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'filepath', 'filename', 'cmdline', 'registry', 'email', 'useragent', 'unknown'];

        const selBlocks   = [];
        const condParts   = [];
        const lsCategories = [];
        const lsProducts = [];

        for (const type of typeOrder) {
            const entries = groups[type];
            if (!entries || entries.length === 0) continue;

            const def = TYPES[type] || TYPES.unknown;
            const selName = `ioc_${type}`;
            const values  = [...new Set(entries.map(e => e.value.trim()).filter(Boolean))];

            const fieldKey = def.modifier ? `${def.sigmaField}|${def.modifier}` : def.sigmaField;
            const valueLines = values.map(v => `      - '${escapeYamlStr(v)}'`).join('\n');

            selBlocks.push(`  ${selName}:\n    ${fieldKey}:\n${valueLines}`);
            condParts.push(selName);

            const ls = def.logsource.category;
            const product = def.logsource.product || '';
            if (!lsCategories.includes(ls)) lsCategories.push(ls);
            if (product && !lsProducts.includes(product)) lsProducts.push(product);
        }

        if (selBlocks.length === 0) return '# No valid IOCs provided.';

        const condition = condParts.length === 1 ? condParts[0] : '1 of ioc_*';

        const totalCount = Object.values(groups).flat().length;
        const typesSummary = Object.keys(groups).filter(t => groups[t]?.length).map(t => TYPES[t]?.label || t).join(', ');

        const descLine = description || `Detects ${totalCount} indicator(s) of compromise — ${typesSummary}. Generated by QueryCast.`;

        // Logsource note if multiple categories are needed
        const multiLsNote = lsCategories.length > 1
            ? `# NOTE: IOCs span multiple log categories (${lsCategories.join(', ')}).\n# Consider splitting into separate rules per category or adjusting logsource.\n`
            : '';

        const primaryCategory = lsCategories[0] || 'process_creation';
        const primaryProduct = lsProducts[0] || 'windows';
        const uuid = generateUUID();
        const today = new Date().toISOString().split('T')[0].replace(/-/g, '/');

        const lines = [
            multiLsNote + `title: '${escapeYamlStr(title)}'`,
            `id: ${uuid}`,
            `status: test`,
            `description: '${escapeYamlStr(descLine)}'`,
            `author: QueryCast IOC Converter`,
            `date: ${today}`,
            `logsource:`,
            `  product: ${primaryProduct}`,
            `  category: ${primaryCategory}`,
            `detection:`,
            ...selBlocks,
            `  condition: ${condition}`,
            `falsepositives:`,
            `  - Unknown`,
            `level: ${level}`,
        ];

        return lines.join('\n');
    }

    // ── Modal state ─────────────────────────────────────────────────────
    let _entries   = [];
    let _overrides = {}; // index → type override
    let _onLoad    = null;
    let _debounce  = null;

    // ── Modal management ────────────────────────────────────────────────

    function init(onLoadRule) {
        _onLoad = onLoadRule;

        // Open button
        document.getElementById('btn-ioc-converter')?.addEventListener('click', open);
        // Close
        document.getElementById('ioc-modal-close')?.addEventListener('click', close);
        document.getElementById('ioc-overlay')?.addEventListener('click', e => {
            if (e.target === document.getElementById('ioc-overlay')) close();
        });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && document.getElementById('ioc-overlay')?.style.display !== 'none') close();
        });

        // Textarea
        document.getElementById('ioc-textarea')?.addEventListener('input', () => {
            clearTimeout(_debounce);
            _debounce = setTimeout(runDetect, 200);
        });

        // CSV upload
        document.getElementById('ioc-csv-input')?.addEventListener('change', handleCSVUpload);
        document.getElementById('ioc-csv-btn')?.addEventListener('click', () => {
            document.getElementById('ioc-csv-input')?.click();
        });

        // Clear
        document.getElementById('ioc-clear-btn')?.addEventListener('click', () => {
            document.getElementById('ioc-textarea').value = '';
            _entries = [];
            _overrides = {};
            renderResults([]);
        });

        // Generate
        document.getElementById('ioc-generate-btn')?.addEventListener('click', generate);

        // Help toggle is a <details> element — native browser behaviour

        // Level select (no listener needed, read on generate)
    }

    function open() {
        const overlay = document.getElementById('ioc-overlay');
        if (overlay) overlay.style.display = 'flex';
        setTimeout(() => document.getElementById('ioc-textarea')?.focus(), 60);
    }

    function close() {
        const overlay = document.getElementById('ioc-overlay');
        if (overlay) overlay.style.display = 'none';
    }

    function handleCSVUpload(e) {
        const file = e.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = ev => {
            const text = ev.target.result;
            const textarea = document.getElementById('ioc-textarea');
            if (textarea) textarea.value = text;
            runDetect(text, true /* isCSV */);
        };
        reader.readAsText(file);
        e.target.value = ''; // reset so same file can be re-uploaded
    }

    function runDetect(overrideText, isCSV) {
        const text = overrideText !== undefined ? overrideText : (document.getElementById('ioc-textarea')?.value || '');
        _overrides = {}; // reset overrides on new parse
        _entries   = isCSV ? parseCSV(text) : parseText(text);
        renderResults(_entries);
    }

    function renderResults(entries) {
        const container = document.getElementById('ioc-results-body');
        const countEl   = document.getElementById('ioc-ioc-count');
        const genBtn    = document.getElementById('ioc-generate-btn');
        if (!container) return;

        const total = entries.length;
        if (countEl) countEl.textContent = total > 0 ? `${total} IOC${total === 1 ? '' : 's'} detected` : '';
        if (genBtn) genBtn.disabled = total === 0;

        if (total === 0) {
            container.innerHTML = `
                <div class="ioc-empty">
                    <i class="bi bi-clipboard-data"></i>
                    <div>Paste or upload IOCs above — one per line.</div>
                    <div style="margin-top:6px;font-size:10px">Supports auto-detection or prefix syntax like <code>ipv4=1.2.3.4</code></div>
                </div>`;
            return;
        }

        // Separate needs-confirm from confirmed
        const ambiguous = entries.filter((e, i) => e.needsConfirm && !_overrides[i]);
        const confirmed = entries.filter((e, i) => !e.needsConfirm || _overrides[i]);

        let html = '';

        // ── Needs Confirmation ──
        if (ambiguous.length > 0) {
            html += `<div class="ioc-section-label"><i class="bi bi-question-circle" style="color:#ffa94d"></i> Needs Confirmation (${ambiguous.length})</div>`;
            for (let i = 0; i < entries.length; i++) {
                const e = entries[i];
                if (!e.needsConfirm || _overrides[i]) continue;

                const allTypes = Object.keys(TYPES).filter(t => t !== 'unknown');
                const optionsHtml = allTypes.map(t =>
                    `<option value="${t}" ${t === e.type ? 'selected' : ''}>${TYPES[t].label}</option>`
                ).join('');

                html += `
                <div class="ioc-item ioc-item-ambiguous" data-idx="${i}">
                    <i class="bi ${TYPES[e.type]?.icon || 'bi-question'} ioc-item-icon" style="color:${TYPES[e.type]?.color || '#868e96'}"></i>
                    <span class="ioc-item-value" title="${escHtml(e.value)}">${escHtml(e.value)}</span>
                    <span class="ioc-ambiguous-badge">uncertain</span>
                    <select class="ioc-type-select" data-idx="${i}" title="Choose IOC type">
                        ${optionsHtml}
                    </select>
                </div>`;
            }
        }

        // ── Confirmed groups ──
        const groups = {};
        for (let i = 0; i < entries.length; i++) {
            const e = entries[i];
            if (e.needsConfirm && !_overrides[i]) continue;
            const type = _overrides[i] || e.type;
            if (!groups[type]) groups[type] = [];
            groups[type].push({ entry: e, idx: i });
        }

        const typeOrder = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'filepath', 'filename', 'cmdline', 'registry', 'email', 'useragent', 'unknown'];
        for (const type of typeOrder) {
            const items = groups[type];
            if (!items || items.length === 0) continue;
            const def = TYPES[type] || TYPES.unknown;

            html += `
            <div class="ioc-group">
                <div class="ioc-group-header">
                    <i class="bi ${def.icon}" style="color:${def.color}"></i>
                    <span>${def.label}</span>
                    <span class="ioc-group-count">${items.length}</span>
                    <span class="ioc-group-field">→ <code>${def.modifier ? `${def.sigmaField}|${def.modifier}` : def.sigmaField}</code></span>
                </div>
                <div class="ioc-group-items">`;

            for (const { entry: e, idx: i } of items) {
                const allTypes = Object.keys(TYPES).filter(t => t !== 'unknown');
                const optHtml  = allTypes.map(t =>
                    `<option value="${t}" ${((_overrides[i] || e.type) === t) ? 'selected' : ''}>${TYPES[t].label}</option>`
                ).join('');
                const prefixBadge = e.prefixed ? `<span class="ioc-prefix-badge" title="Type set by prefix">${e.prefixKey}=</span>` : '';
                const confPct     = Math.round(e.confidence * 100);
                const confBadge   = !e.prefixed ? `<span class="ioc-conf-badge" title="Detection confidence">${confPct}%</span>` : '';

                html += `
                    <div class="ioc-item" data-idx="${i}">
                        ${prefixBadge}${confBadge}
                        <span class="ioc-item-value" title="${escHtml(e.value)}">${escHtml(e.value)}</span>
                        <select class="ioc-type-select ioc-type-select-sm" data-idx="${i}" title="Change type">
                            ${optHtml}
                        </select>
                    </div>`;
            }

            html += `</div></div>`;
        }

        container.innerHTML = html;

        // Bind change events on all type selects
        container.querySelectorAll('.ioc-type-select').forEach(sel => {
            sel.addEventListener('change', () => {
                const idx = parseInt(sel.dataset.idx, 10);
                _overrides[idx] = sel.value;
                // Mark as confirmed
                if (_entries[idx]) _entries[idx].needsConfirm = false;
                renderResults(_entries);
            });
        });
    }

    function _groupByLogsource(entries) {
        const buckets = {};

        for (const e of entries) {
            const type = e.type || 'unknown';
            const def = TYPES[type] || TYPES.unknown;
            const product = def.logsource.product || 'windows';
            const category = def.logsource.category || 'process_creation';
            const key = `${product}/${category}`;

            if (!buckets[key]) {
                buckets[key] = { product, category, groups: {} };
            }
            if (!buckets[key].groups[type]) {
                buckets[key].groups[type] = [];
            }
            buckets[key].groups[type].push(e);
        }

        return buckets;
    }

    async function _tryCopyRulePack(rulePackText) {
        try {
            if (!navigator?.clipboard?.writeText) return false;
            await navigator.clipboard.writeText(rulePackText);
            return true;
        } catch {
            return false;
        }
    }

    async function generate() {
        if (_entries.length === 0) return;

        // Collect effective type for each entry
        const resolved = _entries.map((e, i) => ({
            ...e,
            type: _overrides[i] || e.type || 'unknown',
        }));

        const groups = groupByType(resolved);

        const title   = document.getElementById('ioc-title-input')?.value.trim() || 'IOC Detection';
        const level   = document.getElementById('ioc-level-select')?.value || 'high';
        const descEl  = document.getElementById('ioc-desc-input');
        const desc    = descEl?.value.trim() || '';
        const splitByLogsource = document.getElementById('ioc-split-rules')?.checked === true;

        let yaml = generateSigma(groups, { title, description: desc, level });
        let meta = null;

        if (splitByLogsource) {
            const buckets = Object.values(_groupByLogsource(resolved));
            if (buckets.length > 1) {
                const rules = buckets.map((bucket, idx) => {
                    const suffix = `(${bucket.product}/${bucket.category})`;
                    const ruleTitle = `${title} ${suffix}`;
                    return generateSigma(bucket.groups, {
                        title: ruleTitle,
                        description: desc,
                        level,
                    });
                });

                const pack = rules.join('\n\n---\n\n');
                const copied = await _tryCopyRulePack(pack);

                yaml = rules[0];
                meta = {
                    split: true,
                    total: rules.length,
                    copied,
                    firstLogsource: `${buckets[0].product}/${buckets[0].category}`,
                };
            }
        }

        if (_onLoad) {
            _onLoad(yaml, meta);
            close();
        }
    }

    // tiny HTML escape for rendering
    function escHtml(s) {
        return String(s || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // ── Public API ──────────────────────────────────────────────────────
    return {
        TYPES,
        PREFIX_MAP,
        detectType,
        parseLine,
        parseText,
        parseCSV,
        groupByType,
        generateSigma,
        init,
        open,
        close,
    };

})();
