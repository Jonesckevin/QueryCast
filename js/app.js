/**
 * app.js
 * Main QueryCast application controller.
 * Wires up UI events, recipe management, and output rendering.
 */
'use strict';

const App = (() => {

    // ── DOM references ───────────────────────────────────────────────────
    let inputEl, outputEl, recipeEl, recipeDropzoneEl, opsListEl, opSearchEl;
    let statusBarEl, copyBtn, downloadBtn, clearInputBtn;
    let themeBtn, recipeCountEl, sampleBtn;

    // ── State ────────────────────────────────────────────────────────────
    let _debounceTimer = null;
    let _lastResults   = [];
    let _lastOutputFormat = 'text';
    let _theme = localStorage.getItem('codeswap-theme') || 'dark';
    let _sourceFormat = localStorage.getItem('codeswap-source-format') || 'sigma';

    // Default accent per theme
    const ACCENT_DEFAULTS = { dark: '#4dabf7', light: '#339af0' };

    // ── Accent color helpers ──────────────────────────────────────────────
    function hexToHsl(hex) {
        const r = parseInt(hex.slice(1,3),16)/255, g = parseInt(hex.slice(3,5),16)/255, b = parseInt(hex.slice(5,7),16)/255;
        const max = Math.max(r,g,b), min = Math.min(r,g,b);
        let h, s, l = (max+min)/2;
        if (max === min) { h = s = 0; }
        else {
            const d = max - min;
            s = l > 0.5 ? d/(2-max-min) : d/(max+min);
            switch(max) {
                case r: h = ((g-b)/d + (g<b?6:0))/6; break;
                case g: h = ((b-r)/d + 2)/6; break;
                default: h = ((r-g)/d + 4)/6;
            }
        }
        return [Math.round(h*360), Math.round(s*100), Math.round(l*100)];
    }

    function hslToHex(h, s, l) {
        s /= 100; l /= 100;
        const k = n => (n + h/30) % 12;
        const a = s * Math.min(l, 1-l);
        const f = n => l - a * Math.max(-1, Math.min(k(n)-3, Math.min(9-k(n), 1)));
        return '#' + [f(0),f(8),f(4)].map(v => Math.round(v*255).toString(16).padStart(2,'0')).join('');
    }

    function darkenHex(hex, amount = 12) {
        const [h, s, l] = hexToHsl(hex);
        return hslToHex(h, s, Math.max(0, l - amount));
    }

    function applyAccent(hex) {
        const root = document.documentElement;
        root.style.setProperty('--accent', hex);
        root.style.setProperty('--accent-dark', darkenHex(hex));
        // Update swatch
        const swatch = document.getElementById('accent-swatch');
        if (swatch) swatch.style.background = hex;
        const input = document.getElementById('accent-color-input');
        if (input) input.value = hex;
    }

    // ── Operator logo map (op ID → relative logo path) ──────────────────
    const OP_LOGO_MAP = {
        'sigma-to-splunk':           'logo/splunk.png',
        'splunk-to-sigma':           'logo/splunk.png',
        'sigma-to-elastic':          'logo/elastic-kibana.png',
        'elastic-to-sigma':          'logo/elastic-kibana.png',
        'sigma-to-eql':              'logo/elastic-kibana.png',
        'eql-to-sigma':              'logo/elastic-kibana.png',
        'sigma-to-cb':               'logo/cbcloud.png',
        'cb-to-sigma':               'logo/cbcloud.png',
        'sigma-to-vql':              'logo/velociraptor.png',
        'vql-to-sigma':              'logo/velociraptor.png',
        'sigma-to-aql':              'logo/qradar.png',
        'aql-to-sigma':              'logo/qradar.png',
        'sigma-to-nwql':             'logo/netwitness-logo.png',
        'nwql-to-sigma':             'logo/netwitness-logo.png',
        'sigma-to-ppl':              'logo/opensearch.png',
        'ppl-to-sigma':              'logo/opensearch.png',
        'sigma-to-xql':              'logo/paloalto.png',
        'xql-to-sigma':              'logo/paloalto.png',
        'sigma-to-oql':              'logo/Securonix.png',
        'oql-to-sigma':              'logo/Securonix.png',
        'sigma-to-oql-securityonion':'logo/securityonionsolutions.jpg',
        'sigma-to-arcsight':         'logo/arcsight.png',
        'arcsight-to-sigma':         'logo/arcsight.png',
        'sigma-to-ddql':             'logo/datadog.png',
        'ddql-to-sigma':             'logo/datadog.png',
        'sigma-to-s1ql':             'logo/sentinelone.png',
        's1ql-to-sigma':             'logo/sentinelone.png',
        'sigma-to-graylog':          'logo/greylog.png',
        'graylog-to-sigma':          'logo/greylog.png',
        'sigma-to-sumoql':           'logo/sumo.png',
        'sumo-to-sigma':             'logo/sumo.png',
        'sigma-to-logscale':         'logo/falcon.png',
        'logscale-to-sigma':         'logo/falcon.png',
        'sigma-to-logql':            'logo/grafana.png',
        'logql-to-sigma':            'logo/grafana.png',
        'sigma-to-cwli':             'logo/cloudwatch.png',
        'cwli-to-sigma':             'logo/cloudwatch.png',
        'sigma-to-sysmonxml':        'logo/querycast-logo.svg',
        'sysmonxml-to-sigma':        'logo/querycast-logo.svg',
        'sigma-to-rapid7':           'logo/splunk.png',
        'rapid7-to-sigma':           'logo/splunk.png',
        'sigma-to-anomali':          'logo/paloalto.png',
        'anomali-to-sigma':          'logo/paloalto.png',
        'sigma-to-logger':           'logo/sumo.png',
        'logger-to-sigma':           'logo/sumo.png',
        'sigma-to-elastalert':       'logo/elastic-kibana.png',
        'elastalert-to-sigma':       'logo/elastic-kibana.png',
        'sigma-to-fortisiem':        'logo/qradar.png',
        'fortisiem-to-sigma':        'logo/qradar.png',
        'sigma-to-tanium':           'logo/cbcloud.png',
        'tanium-to-sigma':           'logo/cbcloud.png',
    };

    // ── Init ─────────────────────────────────────────────────────────────
    function init() {
        // Grab DOM
        inputEl       = document.getElementById('input-textarea');
        outputEl      = document.getElementById('output-textarea');
        recipeEl      = document.getElementById('recipe-list');
        opsListEl     = document.getElementById('ops-list');
        opSearchEl    = document.getElementById('ops-search');
        recipeDropzoneEl = document.getElementById('recipe-dropzone');
        statusBarEl   = document.getElementById('status-bar');
        copyBtn       = document.getElementById('btn-copy');
        downloadBtn   = document.getElementById('btn-download');
        clearInputBtn = document.getElementById('btn-clear-input');
        sampleBtn     = document.getElementById('btn-load-sample');
        themeBtn      = document.getElementById('btn-theme');
        recipeCountEl = document.getElementById('recipe-count');

        // Apply saved theme
        applyTheme(_theme);

        // Apply saved accent color
        const savedAccent = localStorage.getItem('codeswap-accent');
        if (savedAccent) {
            applyAccent(savedAccent);
        } else {
            // Sync swatch with CSS default
            const cssAccent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
            const swatch = document.getElementById('accent-swatch');
            if (swatch) swatch.style.background = cssAccent;
            const input = document.getElementById('accent-color-input');
            if (input) input.value = cssAccent.startsWith('#') ? cssAccent : ACCENT_DEFAULTS[_theme];
        }

        // Accent color picker
        document.getElementById('accent-color-input')?.addEventListener('input', e => {
            const hex = e.target.value;
            localStorage.setItem('codeswap-accent', hex);
            applyAccent(hex);
        });
        document.getElementById('accent-reset')?.addEventListener('click', () => {
            localStorage.removeItem('codeswap-accent');
            const def = ACCENT_DEFAULTS[_theme] || ACCENT_DEFAULTS.dark;
            applyAccent(def);
        });
        document.getElementById('accent-swatch')?.closest('label')?.addEventListener('click', () => {
            document.getElementById('accent-color-input')?.click();
        });

        // Render operator list
        renderOperatorList();

        // Recipe change → re-run pipeline
        Recipe.onChangeCallback(() => {
            renderRecipe();
            renderOperatorList(opSearchEl.value || '');
            scheduleRun();
        });

        // Input change → re-run pipeline
        inputEl.addEventListener('input', () => scheduleRun());
        inputEl.addEventListener('paste', () => { setTimeout(scheduleRun, 50); });

        // Operator search
        opSearchEl.addEventListener('input', () => renderOperatorList(opSearchEl.value));

        recipeDropzoneEl?.addEventListener('dragover', e => {
            e.preventDefault();
            recipeDropzoneEl.classList.add('dragover');
        });

        recipeDropzoneEl?.addEventListener('dragleave', () => {
            recipeDropzoneEl.classList.remove('dragover');
        });

        recipeDropzoneEl?.addEventListener('drop', e => {
            e.preventDefault();
            recipeDropzoneEl.classList.remove('dragover');
            const opId = e.dataTransfer.getData('text/op-id');
            if (opId) {
                const op = OperatorsRegistry.getById(opId);
                if (!op) return;
                const currentFormat = getRecipeCurrentFormat();
                if (op.fromFormat && op.fromFormat !== currentFormat) return;
                Recipe.addStep(opId);
                highlightRecipe();
            }
        });

        // Copy output
        copyBtn.addEventListener('click', copyOutput);

        // Download output
        downloadBtn.addEventListener('click', downloadOutput);

        // Clear input
        clearInputBtn.addEventListener('click', () => {
            inputEl.value = '';
            scheduleRun();
        });

        sampleBtn?.addEventListener('click', () => {
            loadSampleRule(_sourceFormat);
            scheduleRun();
        });

        // Sigma DB
        document.getElementById('btn-sigma-db')?.addEventListener('click', () => openSigmaDB());
        document.getElementById('sigma-db-close')?.addEventListener('click', () => closeSigmaDB());
        document.getElementById('sigma-db-overlay')?.addEventListener('click', e => {
            if (e.target === document.getElementById('sigma-db-overlay')) closeSigmaDB();
        });
        document.getElementById('sigma-db-download')?.addEventListener('click', () => sigmaDBDownload());
        document.getElementById('sigma-db-reset')?.addEventListener('click', () => sigmaDBReset());
        document.getElementById('sigma-db-search')?.addEventListener('input', () => sigmaDBSearch());

        // Sigma Help (delegated click handling keeps modal controls resilient)
        document.addEventListener('click', e => {
            const target = e.target?.closest?.(
                '#btn-sigma-help, #sigma-help-close, #sigma-help-close-footer, #sigma-help-load-template'
            );
            if (!target) return;

            if (target.id === 'btn-sigma-help') {
                openSigmaHelp();
                return;
            }

            if (target.id === 'sigma-help-load-template') {
                loadSigmaHelpTemplate();
                return;
            }

            closeSigmaHelp();
        });

        document.getElementById('sigma-help-overlay')?.addEventListener('click', e => {
            if (e.target === document.getElementById('sigma-help-overlay')) closeSigmaHelp();
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') {
                closeSigmaDB();
                closeSigmaHelp();
            }
        });

        // Theme toggle
        themeBtn.addEventListener('click', () => {
            _theme = _theme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('codeswap-theme', _theme);
            applyTheme(_theme);
        });

        // Load sample rule if input is empty
        if (!inputEl.value.trim()) {
            loadSampleRule(_sourceFormat);
        }

        // IOC Converter
        IocConverter.init((yaml, meta) => {
            inputEl.value = yaml;
            scheduleRun();
            if (meta && meta.split) {
                const copyNote = meta.copied ? ' Full rule pack copied to clipboard.' : '';
                setTimeout(() => {
                    setStatus('info', `IOC rule pack generated (${meta.total} rules). Loaded 1/${meta.total} (${meta.firstLogsource}) for conversion.${copyNote}`);
                }, 220);
            } else {
                setTimeout(() => {
                    setStatus('ok', 'IOC Sigma rule loaded — add a conversion operator to transform it.');
                }, 220);
            }
        });

        // AI Assistant
        AiAssistant.init();

        // Mode hint toggle in AI config modal
        document.querySelectorAll('input[name="ai-mode"]').forEach(radio => {
            radio.addEventListener('change', () => {
                const isReview = document.getElementById('ai-cfg-mode-review')?.checked;
                const hintExplain = document.getElementById('ai-mode-hint-explain');
                const hintReview  = document.getElementById('ai-mode-hint-review');
                if (hintExplain) hintExplain.style.display = isReview ? 'none' : 'block';
                if (hintReview)  hintReview.style.display  = isReview ? 'block' : 'none';
            });
        });

        // Show copy/apply buttons after response loads
        const _aiObserver = new MutationObserver(() => {
            const body    = document.getElementById('ai-response-body');
            const copyBtn = document.getElementById('ai-response-copy');
            if (body && copyBtn && body.style.display !== 'none') {
                copyBtn.style.display = 'inline-flex';
            }
        });
        const aiBody = document.getElementById('ai-response-body');
        if (aiBody) _aiObserver.observe(aiBody, { attributes: true, attributeFilter: ['style'] });

        // Initial render
        renderRecipe();
        scheduleRun();

        // Keyboard shortcut: Ctrl+Enter to run
        document.addEventListener('keydown', e => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                runNow();
            }
        });
    }

    // ── Theme ────────────────────────────────────────────────────────────
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        const icon = document.getElementById('theme-icon');
        if (icon) icon.className = theme === 'dark' ? 'bi bi-sun' : 'bi bi-moon-stars';
        // If no custom accent, sync swatch to the theme's default
        if (!localStorage.getItem('codeswap-accent')) {
            const def = ACCENT_DEFAULTS[theme] || ACCENT_DEFAULTS.dark;
            const swatch = document.getElementById('accent-swatch');
            if (swatch) swatch.style.background = def;
            const input = document.getElementById('accent-color-input');
            if (input) input.value = def;
        }
    }

    // ── Operator List Rendering ──────────────────────────────────────────
    function renderOperatorList(filter = '') {
        const categories = OperatorsRegistry.getCategories();
        const allOps     = OperatorsRegistry.getAll();
        const query      = filter.toLowerCase().trim();

        opsListEl.innerHTML = '';

        const currentFormat = getRecipeCurrentFormat();

        for (const cat of categories) {
            const opsInCat = allOps.filter(op =>
                op.category === cat.id &&
                (!currentFormat || op.fromFormat === currentFormat || !op.fromFormat) &&
                (!query || op.name.toLowerCase().includes(query) || op.description.toLowerCase().includes(query))
            );

            if (opsInCat.length === 0) continue;

            const catEl = document.createElement('div');
            catEl.className = 'ops-category';
            catEl.innerHTML = `
                <div class="ops-category-header">
                    <i class="bi ${cat.icon}"></i>
                    <span>${cat.label}</span>
                </div>
            `;

            for (const op of opsInCat) {
                const opEl = document.createElement('div');
                opEl.className = 'op-item';
                opEl.dataset.opId = op.id;
                opEl.draggable = true;
                opEl.style.setProperty('--op-color', op.color || '#4dabf7');
                const logoPath = OP_LOGO_MAP[op.id];
                const logoHtml = logoPath
                    ? `<img class="op-logo" src="${logoPath}" alt="" draggable="false">`
                    : '';
                opEl.innerHTML = `
                    <i class="bi ${op.icon} op-icon"></i>
                    <div class="op-item-text">
                        <div class="op-item-name">${escapeHtml(op.name)}</div>
                        <div class="op-item-desc">${escapeHtml(op.description)}</div>
                    </div>
                    ${logoHtml}
                    <button class="op-add-btn" title="Drag or click to add" aria-label="Add ${escapeHtml(op.name)}">
                        <i class="bi bi-plus-lg"></i>
                    </button>
                `;
                opEl.querySelector('.op-add-btn').addEventListener('click', (e) => {
                    e.stopPropagation();
                    Recipe.addStep(op.id);
                    highlightRecipe();
                });
                opEl.addEventListener('click', () => {
                    Recipe.addStep(op.id);
                    highlightRecipe();
                });
                opEl.addEventListener('dragstart', e => {
                    e.dataTransfer.setData('text/op-id', op.id);
                    e.dataTransfer.effectAllowed = 'copy';
                    opEl.classList.add('dragging');
                });
                opEl.addEventListener('dragend', () => {
                    opEl.classList.remove('dragging');
                });
                catEl.appendChild(opEl);
            }

            opsListEl.appendChild(catEl);
        }

        if (opsListEl.innerHTML === '') {
            const scopeLabel = currentFormat ? OperatorsRegistry.getInputFormatLabel(currentFormat) : 'available input format';
            opsListEl.innerHTML = `<div class="ops-empty">No operators match "${escapeHtml(filter)}" for ${escapeHtml(scopeLabel)}</div>`;
        }
    }

    function getRecipeCurrentFormat() {
        const steps = Recipe.getSteps();
        const enabledSteps = steps.filter(s => !s.disabled);
        if (enabledSteps.length === 0) return null;

        let format = enabledSteps[0] ? (OperatorsRegistry.getById(enabledSteps[0].opId)?.fromFormat || _sourceFormat) : _sourceFormat;
        for (const step of steps) {
            if (step.disabled) continue;
            const op = OperatorsRegistry.getById(step.opId);
            if (!op) continue;
            format = op.toFormat || format;
        }
        return format;
    }

    function pruneIncompatibleSteps() {
        const steps = Recipe.getSteps();
        let format = 'sigma';
        const incompatible = steps.filter(step => {
            const op = OperatorsRegistry.getById(step.opId);
            const isIncompatible = op && op.fromFormat && op.fromFormat !== format;
            if (!isIncompatible && op) {
                format = op.toFormat || format;
            }
            return isIncompatible;
        });

        incompatible.forEach(step => Recipe.removeStep(step.stepId));
    }

    // ── Recipe Rendering ─────────────────────────────────────────────────
    function renderRecipe() {
        const steps = Recipe.getSteps();

        // Update count badge
        recipeCountEl.textContent = steps.length;
        recipeCountEl.style.display = steps.length > 0 ? 'inline-flex' : 'none';

        if (steps.length === 0) {
            recipeEl.innerHTML = `
                <div class="recipe-empty">
                    <i class="bi bi-arrow-left-circle"></i>
                    <p>Drag an operator here or click one to add it to the recipe</p>
                </div>
            `;
            return;
        }

        recipeEl.innerHTML = '';
        steps.forEach((step, idx) => {
            const op = OperatorsRegistry.getById(step.opId);
            if (!op) return;

            const stepEl = document.createElement('div');
            stepEl.className = `recipe-step ${step.disabled ? 'disabled' : ''} ${step.error ? 'has-error' : ''}`;
            stepEl.dataset.stepId = step.stepId;
            stepEl.style.setProperty('--op-color', op.color || '#4dabf7');

            // Build options HTML
            const optsHtml = (op.options || []).map(opt => buildOptionHtml(step, opt)).join('');

            stepEl.innerHTML = `
                <div class="step-header">
                    <span class="step-number">${idx + 1}</span>
                    <i class="bi ${op.icon} step-icon"></i>
                    <span class="step-name">${escapeHtml(op.name)}</span>
                    <div class="step-actions">
                        <button class="step-btn step-btn-up" title="Move up" ${idx === 0 ? 'disabled' : ''}>
                            <i class="bi bi-chevron-up"></i>
                        </button>
                        <button class="step-btn step-btn-down" title="Move down" ${idx === steps.length - 1 ? 'disabled' : ''}>
                            <i class="bi bi-chevron-down"></i>
                        </button>
                        <button class="step-btn step-btn-toggle" title="${step.disabled ? 'Enable' : 'Disable'}">
                            <i class="bi bi-${step.disabled ? 'play-circle' : 'pause-circle'}"></i>
                        </button>
                        <button class="step-btn step-btn-remove" title="Remove">
                            <i class="bi bi-x-lg"></i>
                        </button>
                    </div>
                </div>
                ${optsHtml.length ? `<div class="step-options">${optsHtml}</div>` : ''}
                ${step.error ? `<div class="step-error"><i class="bi bi-exclamation-triangle"></i> ${escapeHtml(step.error)}</div>` : ''}
            `;

            // Bind step action buttons
            stepEl.querySelector('.step-btn-up')?.addEventListener('click', () => Recipe.moveStep(step.stepId, 'up'));
            stepEl.querySelector('.step-btn-down')?.addEventListener('click', () => Recipe.moveStep(step.stepId, 'down'));
            stepEl.querySelector('.step-btn-toggle')?.addEventListener('click', () => Recipe.toggleDisabled(step.stepId));
            stepEl.querySelector('.step-btn-remove')?.addEventListener('click', () => Recipe.removeStep(step.stepId));

            // Bind option inputs
            stepEl.querySelectorAll('[data-option-id]').forEach(el => {
                el.addEventListener('change', () => {
                    const optId = el.dataset.optionId;
                    const val   = el.type === 'checkbox' ? el.checked : el.value;
                    Recipe.setOption(step.stepId, optId, val);
                });
            });

            recipeEl.appendChild(stepEl);
        });
    }

    function buildOptionHtml(step, opt) {
        const val = step.opts[opt.id];
        if (opt.type === 'checkbox') {
            return `
                <label class="step-option-row">
                    <input type="checkbox" class="step-opt-input" data-option-id="${opt.id}" ${val ? 'checked' : ''}>
                    <span>${escapeHtml(opt.label)}</span>
                </label>`;
        }
        if (opt.type === 'select') {
            const optsHtml = opt.options.map(o =>
                `<option value="${o.value}" ${o.value === val ? 'selected' : ''}>${escapeHtml(o.label)}</option>`
            ).join('');
            return `
                <label class="step-option-row">
                    <span>${escapeHtml(opt.label)}</span>
                    <select class="step-opt-select step-opt-input" data-option-id="${opt.id}">${optsHtml}</select>
                </label>`;
        }
        if (opt.type === 'number') {
            return `
                <label class="step-option-row">
                    <span>${escapeHtml(opt.label)}</span>
                    <input type="number" class="step-opt-input" data-option-id="${opt.id}"
                        value="${val}" min="${opt.min || 0}" max="${opt.max || 999999}">
                </label>`;
        }
        return '';
    }

    // ── Pipeline Execution ───────────────────────────────────────────────
    function scheduleRun() {
        clearTimeout(_debounceTimer);
        _debounceTimer = setTimeout(runNow, 150);
    }

    function runNow() {
        const input = inputEl.value;
        const steps = Recipe.getSteps();

        if (steps.length === 0) {
            outputEl.value = '';
            setStatus('info', 'Add operators to the recipe to convert your query.');
            return;
        }

        if (!input.trim()) {
            outputEl.value = '';
            setStatus('info', 'Paste or type your source query into the Input panel.');
            return;
        }

        const initialFormat = inferInitialFormat(steps, input);
        const { results, finalOutput } = Recipe.run(input, initialFormat);
        _lastResults = results;
        const lastEnabledStep = [...steps].reverse().find(s => !s.disabled);
        if (lastEnabledStep) {
            const lastOp = OperatorsRegistry.getById(lastEnabledStep.opId);
            _lastOutputFormat = (lastOp && lastOp.toFormat) ? lastOp.toFormat : 'text';
        } else {
            _lastOutputFormat = 'text';
        }

        outputEl.value = finalOutput || '';

        // Update step error states
        results.forEach(r => {
            const stepEl = recipeEl.querySelector(`[data-step-id="${r.stepId}"]`);
            if (!stepEl) return;
            const errorDiv = stepEl.querySelector('.step-error');

            if (r.error) {
                stepEl.classList.add('has-error');
                if (!errorDiv) {
                    const div = document.createElement('div');
                    div.className = 'step-error';
                    div.innerHTML = `<i class="bi bi-exclamation-triangle"></i> ${escapeHtml(r.error)}`;
                    stepEl.appendChild(div);
                } else {
                    errorDiv.innerHTML = `<i class="bi bi-exclamation-triangle"></i> ${escapeHtml(r.error)}`;
                }
            } else {
                stepEl.classList.remove('has-error');
                errorDiv?.remove();
            }
        });

        // Status bar
        const errors = results.filter(r => r.error);
        const totalMs = results.reduce((s, r) => s + (r.durationMs || 0), 0);

        if (errors.length > 0) {
            setStatus('error', `${errors.length} error(s) in pipeline — check step(s) above. (${totalMs}ms)`);
        } else {
            const lineCount = (finalOutput || '').split('\n').length;
            setStatus('ok', `${steps.filter(s => !s.disabled).length} step(s) completed · ${lineCount} lines · ${totalMs}ms`);
        }

        // Syntax highlight output
        highlightOutput();
    }

    function inferInitialFormat(steps, input) {
        const firstEnabled = steps.find(s => !s.disabled);
        if (firstEnabled) {
            const firstOp = OperatorsRegistry.getById(firstEnabled.opId);
            if (firstOp && firstOp.fromFormat) return firstOp.fromFormat;
        }

        const text = String(input || '');
        if (/^\s*(title|id|logsource|detection)\s*:/m.test(text)) return 'sigma';
        if (/\|\s*where\b/i.test(text) || /\bstartswith\b|\bcontains\b|\bin~\b/i.test(text)) return 'kql';
        if (/\bindex\s*=|\bsource\s*=|\bEventCode\s*=|\w+\s*=\s*"[^"]+"/i.test(text)) return 'splunk';
        if (/\w+\s*:\s*(\*|"|\/|\w)/.test(text)) return 'elastic';

        return _sourceFormat;
    }

    function highlightOutput() {
        const el = document.getElementById('output-highlight');
        if (!el) return;

        el.className = 'hljs querycast-highlight';
        el.innerHTML = renderCustomHighlight(outputEl.value || '');
    }

    function renderCustomHighlight(text) {
        return String(text || '')
            .split('\n')
            .map(line => renderHighlightedLine(line))
            .join('\n');
    }

    function renderHighlightedLine(line) {
        if (isCommentLine(line)) {
            return `<span class="tok-comment">${escapeHtml(line)}</span>`;
        }

        const tokens = tokenizeLine(line);
        annotateAssignments(tokens);

        let depth = 0;
        return tokens.map(token => {
            if (token.type === 'bracket') {
                const open = '([{'.includes(token.value);
                const close = ')]}'.includes(token.value);

                if (close) depth = Math.max(0, depth - 1);
                const className = `tok-bracket tok-bracket-${depth % 6}`;
                if (open) depth += 1;

                return `<span class="${className}">${escapeHtml(token.value)}</span>`;
            }

            if (token.type === 'sep') {
                return `<span class="tok-sep">${escapeHtml(token.value)}</span>`;
            }

            if (token.type === 'word' && /^(and|or|not)$/i.test(token.value)) {
                return `<span class="tok-bool">${escapeHtml(token.value)}</span>`;
            }

            if (token.role === 'filter') {
                return `<span class="tok-filter">${escapeHtml(token.value)}</span>`;
            }

            if (token.role === 'value') {
                return `<span class="tok-value">${escapeHtml(token.value)}</span>`;
            }

            if (token.type === 'quoted') {
                return `<span class="tok-value">${escapeHtml(token.value)}</span>`;
            }

            return escapeHtml(token.value);
        }).join('');
    }

    function isCommentLine(line) {
        const trimmed = String(line || '').trim();
        if (!trimmed) return false;
        return trimmed.startsWith('#') ||
            trimmed.startsWith('//') ||
            trimmed.startsWith('--') ||
            trimmed.startsWith('/*') ||
            trimmed.startsWith('*') ||
            trimmed.startsWith('*/');
    }

    function tokenizeLine(line) {
        const tokens = [];
        const src = String(line || '');
        let i = 0;

        while (i < src.length) {
            const ch = src[i];

            if (/\s/.test(ch)) {
                let j = i + 1;
                while (j < src.length && /\s/.test(src[j])) j += 1;
                tokens.push({ type: 'ws', value: src.slice(i, j) });
                i = j;
                continue;
            }

            if (ch === '"' || ch === "'") {
                const quote = ch;
                let j = i + 1;
                while (j < src.length) {
                    if (src[j] === '\\' && j + 1 < src.length) {
                        j += 2;
                        continue;
                    }
                    if (src[j] === quote) {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                tokens.push({ type: 'quoted', value: src.slice(i, j) });
                i = j;
                continue;
            }

            if (ch === ':' || ch === '=') {
                tokens.push({ type: 'sep', value: ch });
                i += 1;
                continue;
            }

            if ('()[]{}'.includes(ch)) {
                tokens.push({ type: 'bracket', value: ch });
                i += 1;
                continue;
            }

            if (isWordChar(ch)) {
                let j = i + 1;
                while (j < src.length && isWordChar(src[j])) j += 1;
                tokens.push({ type: 'word', value: src.slice(i, j) });
                i = j;
                continue;
            }

            tokens.push({ type: 'punct', value: ch });
            i += 1;
        }

        return tokens;
    }

    function annotateAssignments(tokens) {
        for (let i = 0; i < tokens.length; i += 1) {
            if (tokens[i].type !== 'sep') continue;

            const left = findPrevSignificantToken(tokens, i - 1);
            if (left && (left.type === 'word' || left.type === 'quoted')) {
                left.role = 'filter';
            }

            const rightIdx = findNextSignificantIndex(tokens, i + 1);
            if (rightIdx < 0) continue;

            let j = rightIdx;
            while (j < tokens.length) {
                const tok = tokens[j];

                if (tok.type === 'sep') break;
                if (tok.type === 'ws') {
                    j += 1;
                    continue;
                }
                if (tok.type === 'bracket' && ')]}'.includes(tok.value)) break;
                if (tok.type === 'word' && /^(and|or|not)$/i.test(tok.value)) break;
                if (tok.type === 'punct' && (tok.value === ',' || tok.value === '|')) break;
                if (tok.type === 'bracket') {
                    j += 1;
                    continue;
                }

                tok.role = 'value';
                j += 1;

                // Quoted values and atomic words are complete values.
                if (tok.type === 'quoted' || tok.type === 'word') {
                    break;
                }
            }
        }
    }

    function findPrevSignificantToken(tokens, fromIdx) {
        for (let i = fromIdx; i >= 0; i -= 1) {
            if (tokens[i].type === 'ws') continue;
            return tokens[i];
        }
        return null;
    }

    function findNextSignificantIndex(tokens, fromIdx) {
        for (let i = fromIdx; i < tokens.length; i += 1) {
            if (tokens[i].type === 'ws') continue;
            return i;
        }
        return -1;
    }

    function isWordChar(ch) {
        return /[A-Za-z0-9_.@$\\\/\-*?]/.test(ch);
    }

    // ── Status Bar ───────────────────────────────────────────────────────
    function setStatus(level, message) {
        statusBarEl.className = `status-bar status-${level}`;
        statusBarEl.innerHTML = `<i class="bi bi-${level === 'ok' ? 'check-circle' : level === 'error' ? 'exclamation-circle' : 'info-circle'}"></i> ${escapeHtml(message)}`;
    }

    // ── Copy / Download ──────────────────────────────────────────────────
    function copyOutput() {
        if (!outputEl.value) return;
        navigator.clipboard.writeText(outputEl.value).then(() => {
            const orig = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
            setTimeout(() => { copyBtn.innerHTML = orig; }, 2000);
        }).catch(() => {
            outputEl.select();
            document.execCommand('copy');
        });
    }

    function downloadOutput() {
        if (!outputEl.value) return;
        const steps = Recipe.getSteps();
        const lastOp = steps.length ? OperatorsRegistry.getById(steps[steps.length - 1].opId) : null;
        const ext = lastOp ? {
            splunk: 'spl', elastic: 'txt', kql: 'kql', cb: 'txt', vql: 'vql', json: 'json',
            aql: 'aql', ppl: 'ppl', xql: 'xql', oql: 'oql', arcsight: 'arcsight', ddql: 'ddql', s1ql: 's1ql', eql: 'eql', yaral: 'yaral',
            graylog: 'graylog', sumoql: 'sumo', logscale: 'logscale', logql: 'logql', cwli: 'cwli', udm: 'udm'
        }[lastOp.toFormat] || 'txt' : 'txt';

        const blob = new Blob([outputEl.value], { type: 'text/plain;charset=utf-8' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `converted.${ext}`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ── Sample Rule ──────────────────────────────────────────────────────
    function loadSampleRule(format = 'sigma') {
        if (format === 'splunk') {
            inputEl.value = `index=wineventlog source="WinEventLog:Security" EventCode=4688 (NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe") CommandLine="* -enc *"`;
            return;
        }
        if (format === 'elastic') {
            inputEl.value = `event.code:4688 AND (process.executable:*\\powershell.exe OR process.executable:*\\pwsh.exe) AND process.command_line:* -enc *`;
            return;
        }
        if (format === 'kql') {
            inputEl.value = `SecurityEvent\n| where EventID == 4688\n| where NewProcessName endswith "\\powershell.exe" or NewProcessName endswith "\\pwsh.exe"\n| where CommandLine contains " -enc "`;
            return;
        }
        if (format === 'cb') {
            inputEl.value = `process_name:powershell.exe cmdline:* -enc *`;
            return;
        }
        if (format === 'vql') {
            inputEl.value = `SELECT *\nFROM Windows.EventLogs.Evtx(EvtxGlob="C:/Windows/System32/winevt/Logs/Security.evtx")\nWHERE EventID = 4688 AND CommandLine =~ '(?i).* -enc .*'\nLIMIT 100`;
            return;
        }

        inputEl.value = `title: Suspicious PowerShell Encoded Command
id: b64e2468-e2e7-4d89-b23a-89bf7f9d5a12
status: experimental
description: Detects execution of PowerShell with base64-encoded command line arguments often used to evade detection
author: QueryCast Example
date: 2024-01-15
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -e '
    filter_legit:
        ParentImage|endswith:
            - '\\vscode\\code.exe'
            - '\\windowsapps\\microsoft.windowsterminal_'
    condition: selection and not filter_legit
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentImage
falsepositives:
    - Development tools using PowerShell with encoded commands
    - Legitimate automation scripts
level: high`;
    }

    // ── Helpers ──────────────────────────────────────────────────────────
    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function highlightRecipe() {
        // Brief flash on recipe area to indicate a step was added
        recipeEl.classList.add('flash');
        setTimeout(() => recipeEl.classList.remove('flash'), 300);
    }

    // ── Sigma DB UI ──────────────────────────────────────────────────────
    function openSigmaDB() {
        const overlay = document.getElementById('sigma-db-overlay');
        if (!overlay) return;
        overlay.style.display = 'flex';

        // Load meta to show cached state
        SigmaDB.getMeta().then(meta => {
            const metaEl = document.getElementById('sigma-db-meta');
            if (meta && meta.count) {
                metaEl.textContent = `${meta.count.toLocaleString()} rules cached · ${new Date(meta.updatedAt).toLocaleDateString()}`;
                sigmaDBSearch(); // show all results
            } else {
                metaEl.textContent = 'No local cache';
            }
        });

        setTimeout(() => document.getElementById('sigma-db-search')?.focus(), 50);
    }

    function closeSigmaDB() {
        const overlay = document.getElementById('sigma-db-overlay');
        if (overlay) overlay.style.display = 'none';
    }

        function openSigmaHelp() {
                const overlay = document.getElementById('sigma-help-overlay');
                if (!overlay) return;
                overlay.style.display = 'flex';
        }

        function closeSigmaHelp() {
                const overlay = document.getElementById('sigma-help-overlay');
                if (overlay) overlay.style.display = 'none';
        }

        function loadSigmaHelpTemplate() {
                inputEl.value = `title: Example Sigma Starter Rule
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Example template showing proper Sigma structure
author: QueryCast User
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
        CommandLine|contains:
            - ' -enc '
    filter_legit:
        ParentImage|endswith:
            - '\\vscode\\code.exe'
    condition: selection and not filter_legit
level: high`;
                closeSigmaHelp();
                scheduleRun();
                setStatus('ok', 'Sigma starter template loaded into Input.');
        }

    async function sigmaDBDownload() {
        const btn      = document.getElementById('sigma-db-download');
        const statusEl = document.getElementById('sigma-db-status');
        const statusTx = document.getElementById('sigma-db-status-text');
        const progressEl = document.getElementById('sigma-db-progress');
        const metaEl   = document.getElementById('sigma-db-meta');

        btn.disabled = true;
        progressEl.style.width = '0%';
        statusEl.className = 'sigma-db-status downloading';

        function setStatus(msg, pct) {
            statusTx.textContent = msg;
            if (pct !== undefined) progressEl.style.width = `${pct}%`;
        }

        try {
            const result = await SigmaDB.download(({ phase, done, total, errorCount }) => {
                if (phase === 'tree') {
                    setStatus('Fetching rule list from GitHub…', 2);
                } else if (phase === 'download') {
                    const pct = total > 0 ? Math.round((done / total) * 90) + 5 : 5;
                    setStatus(`Downloading rules… ${done.toLocaleString()} / ${total.toLocaleString()}`, pct);
                } else if (phase === 'saving') {
                    setStatus('Saving to local database…', 96);
                } else if (phase === 'done') {
                    setStatus(`Done. ${done.toLocaleString()} rules saved.${errorCount ? ` (${errorCount} skipped)` : ''}`, 100);
                }
            });

            statusEl.className = 'sigma-db-status ok';
            statusTx.textContent = `Download complete — ${result.count.toLocaleString()} rules available.${result.errorCount ? ` (${result.errorCount} fetch errors)` : ''}`;
            metaEl.textContent   = `${result.count.toLocaleString()} rules cached · ${new Date().toLocaleDateString()}`;
            sigmaDBSearch();

        } catch (err) {
            statusEl.className = 'sigma-db-status error';
            statusTx.textContent = `Error: ${err.message}`;
        } finally {
            btn.disabled = false;
        }
    }

    async function sigmaDBReset() {
        const resetBtn = document.getElementById('sigma-db-reset');
        const dlBtn    = document.getElementById('sigma-db-download');
        const statusEl = document.getElementById('sigma-db-status');
        const statusTx = document.getElementById('sigma-db-status-text');
        const progressEl = document.getElementById('sigma-db-progress');
        const metaEl   = document.getElementById('sigma-db-meta');
        const searchEl = document.getElementById('sigma-db-search');
        const resultsEl = document.getElementById('sigma-db-results');

        let allowReset = false;
        try {
            const typed = window.prompt('Type RESET to confirm deleting all locally cached Sigma rules.', '');
            if (typed === null) return;
            allowReset = typed.trim() === 'RESET';
            if (!allowReset) {
                if (statusEl) statusEl.className = 'sigma-db-status error';
                if (statusTx) statusTx.textContent = 'Reset cancelled. You must type RESET exactly.';
                return;
            }
        } catch {
            const confirmed = window.confirm('Prompt is unavailable here. Delete all locally cached Sigma rules now?');
            if (!confirmed) return;
            const confirmedAgain = window.confirm('Final confirmation: This permanently deletes the local Sigma DB cache. Continue?');
            if (!confirmedAgain) return;
            allowReset = true;
        }

        if (!allowReset) return;

        if (resetBtn) resetBtn.disabled = true;
        if (dlBtn) dlBtn.disabled = true;
        if (progressEl) progressEl.style.width = '20%';
        if (statusEl) statusEl.className = 'sigma-db-status downloading';
        if (statusTx) statusTx.textContent = 'Deleting local Sigma DB cache...';

        try {
            await SigmaDB.reset();

            if (progressEl) progressEl.style.width = '100%';
            if (statusEl) statusEl.className = 'sigma-db-status ok';
            if (statusTx) statusTx.textContent = 'Local Sigma DB cache deleted.';
            if (metaEl) metaEl.textContent = 'No local cache';
            if (searchEl) searchEl.value = '';

            if (resultsEl) {
                resultsEl.innerHTML = '<div class="sigma-db-empty"><i class="bi bi-cloud-download"></i><div>Cache cleared. Click <strong>Download Rules</strong> to fetch rules again.</div></div>';
            }
        } catch (err) {
            if (statusEl) statusEl.className = 'sigma-db-status error';
            if (statusTx) statusTx.textContent = `Reset failed: ${err.message}`;
            if (progressEl) progressEl.style.width = '0%';
        } finally {
            if (resetBtn) resetBtn.disabled = false;
            if (dlBtn) dlBtn.disabled = false;
        }
    }

    async function sigmaDBSearch() {
        const searchEl  = document.getElementById('sigma-db-search');
        const resultsEl = document.getElementById('sigma-db-results');
        if (!resultsEl) return;

        const query = (searchEl?.value || '').trim();

        let rules;
        try {
            rules = await SigmaDB.search(query, 300);
        } catch {
            rules = [];
        }

        if (rules.length === 0) {
            const msg = query
                ? `No rules match "<strong>${escapeHtml(query)}</strong>".`
                : 'No rules cached. Click <strong>Download Rules</strong> to fetch them.';
            resultsEl.innerHTML = `<div class="sigma-db-empty"><i class="bi bi-search"></i><div>${msg}</div></div>`;
            return;
        }

        resultsEl.innerHTML = '';
        for (const rule of rules) {
            const item = document.createElement('div');
            item.className = 'sigma-db-result-item';

            const levelColor = { critical: '#ff6b6b', high: '#ffa94d', medium: '#ffd43b', low: '#74c0fc', informational: '#51cf66' }[rule.level] || 'var(--text-muted)';
            const tagsHtml   = (rule.tags || []).slice(0, 4).map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('');

            item.innerHTML = `
                <div class="sigma-db-result-title">${escapeHtml(rule.title || rule.path)}</div>
                <div class="sigma-db-result-meta">
                    ${rule.level ? `<span style="color:${levelColor}">${escapeHtml(rule.level)}</span>` : ''}
                    ${rule.category ? `<span>${escapeHtml(rule.category)}${rule.subcategory ? '/' + escapeHtml(rule.subcategory) : ''}</span>` : ''}
                    ${rule.status ? `<span>${escapeHtml(rule.status)}</span>` : ''}
                    ${tagsHtml}
                </div>
            `;

            item.addEventListener('click', () => {
                inputEl.value = rule.raw;
                scheduleRun();
                closeSigmaDB();
                setStatus('ok', `Loaded: ${rule.title || rule.path}`);
            });

            resultsEl.appendChild(item);
        }
    }

    return { init };
})();

// Bootstrap
document.addEventListener('DOMContentLoaded', App.init);

function querycastSigmaHelpTemplateText() {
    return `title: Example Sigma Starter Rule
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Example template showing proper Sigma structure
author: QueryCast User
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
        CommandLine|contains:
            - ' -enc '
    filter_legit:
        ParentImage|endswith:
            - '\\vscode\\code.exe'
    condition: selection and not filter_legit
level: high`;
}

window.querycastSigmaHelpOpen = function querycastSigmaHelpOpen() {
    const overlay = document.getElementById('sigma-help-overlay');
    if (overlay) overlay.style.display = 'flex';
};

window.querycastSigmaHelpClose = function querycastSigmaHelpClose() {
    const overlay = document.getElementById('sigma-help-overlay');
    if (overlay) overlay.style.display = 'none';
};

window.querycastSigmaHelpLoadTemplate = function querycastSigmaHelpLoadTemplate() {
    const inputEl = document.getElementById('input-textarea');
    if (inputEl) {
        inputEl.value = querycastSigmaHelpTemplateText();
        inputEl.dispatchEvent(new Event('input', { bubbles: true }));
    }
    window.querycastSigmaHelpClose();
};

// Fallback Sigma Help controls: ensures modal works even if init-time bindings are skipped.
document.addEventListener('click', e => {
    const trigger = e.target?.closest?.(
        '#btn-sigma-help, #sigma-help-close, #sigma-help-close-footer, #sigma-help-load-template'
    );
    if (!trigger) return;

    const overlay = document.getElementById('sigma-help-overlay');
    if (!overlay) return;

    if (trigger.id === 'btn-sigma-help') {
        window.querycastSigmaHelpOpen();
        return;
    }

    if (trigger.id === 'sigma-help-load-template') {
        window.querycastSigmaHelpLoadTemplate();
        return;
    }

    window.querycastSigmaHelpClose();
});
