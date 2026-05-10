/**
 * ai-assistant.js
 * AI query assistant for QueryCast — explain or review/fix SIEM query output.
 *
 * Supports: OpenAI, Anthropic, Gemini, Groq, OpenRouter, DeepSeek, Mistral,
 *           Grok (X.AI), Cohere, Cerebras, Perplexity, Ollama (local), LM Studio (local).
 *
 * All settings are stored in localStorage (no server required).
 */
'use strict';

const AiAssistant = (() => {

    const STORAGE_KEY = 'codeswap-ai-config';

    // ── Provider definitions ────────────────────────────────────────────
    const PROVIDERS = {
        openai:     { name: 'OpenAI',           baseURL: 'https://api.openai.com/v1',                    format: 'openai',    requiresKey: true,  defaultModel: 'gpt-4o-mini',                              local: false },
        anthropic:  { name: 'Anthropic',         baseURL: 'https://api.anthropic.com/v1',                 format: 'anthropic', requiresKey: true,  defaultModel: 'claude-3-5-haiku-20241022',                local: false },
        gemini:     { name: 'Google Gemini',     baseURL: 'https://generativelanguage.googleapis.com/v1beta', format: 'gemini', requiresKey: true, defaultModel: 'gemini-1.5-flash',                       local: false },
        groq:       { name: 'Groq',              baseURL: 'https://api.groq.com/openai/v1',               format: 'openai',    requiresKey: true,  defaultModel: 'llama-3.3-70b-versatile',                  local: false },
        openrouter: { name: 'OpenRouter',        baseURL: 'https://openrouter.ai/api/v1',                 format: 'openai',    requiresKey: true,  defaultModel: 'meta-llama/llama-3.3-70b-instruct:free',   local: false },
        deepseek:   { name: 'DeepSeek',          baseURL: 'https://api.deepseek.com',                     format: 'openai',    requiresKey: true,  defaultModel: 'deepseek-chat',                            local: false },
        mistral:    { name: 'Mistral AI',        baseURL: 'https://api.mistral.ai/v1',                    format: 'openai',    requiresKey: true,  defaultModel: 'mistral-small-latest',                     local: false },
        grok:       { name: 'Grok (X.AI)',       baseURL: 'https://api.x.ai/v1',                          format: 'openai',    requiresKey: true,  defaultModel: 'grok-3-mini',                              local: false },
        cohere:     { name: 'Cohere',            baseURL: 'https://api.cohere.ai/compatibility/v1',       format: 'openai',    requiresKey: true,  defaultModel: 'command-r-plus',                           local: false },
        cerebras:   { name: 'Cerebras',          baseURL: 'https://api.cerebras.ai/v1',                   format: 'openai',    requiresKey: true,  defaultModel: 'llama-3.3-70b',                            local: false },
        perplexity: { name: 'Perplexity',        baseURL: 'https://api.perplexity.ai',                    format: 'openai',    requiresKey: true,  defaultModel: 'sonar',                                   local: false },
        ollama:     { name: 'Ollama (Local)',     baseURL: 'http://localhost:11434/v1',                    format: 'openai',    requiresKey: false, defaultModel: 'llama3.2',                                 local: true  },
        lmstudio:   { name: 'LM Studio (Local)', baseURL: 'http://localhost:1234/v1',                     format: 'openai',    requiresKey: false, defaultModel: 'local-model',                              local: true  },
    };

    // ── Default config ──────────────────────────────────────────────────
    const DEFAULT_CONFIG = {
        provider:       'openai',
        model:          '',
        apiKey:         '',
        mode:           'explain',      // 'explain' | 'review'
        customPrompt:   '',
        localIp:        'localhost',
        localPort:      '',             // empty → use provider default port
        enabledClouds:  [],
        version:        1,
    };

    let _cfg = { ...DEFAULT_CONFIG };

    // ── Load / save ─────────────────────────────────────────────────────
    function _loadConfig() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) _cfg = { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
        } catch { /**/ }
    }

    function _saveConfig() {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(_cfg));
    }

    // ── Build effective base URL for local providers ─────────────────────
    function _getBaseURL(providerId) {
        const p = PROVIDERS[providerId];
        if (!p) return '';
        if (!p.local) return p.baseURL;
        const ip   = (_cfg.localIp   || 'localhost').trim();
        const port = (_cfg.localPort || '').trim();
        if (!port) return p.baseURL; // keep provider default
        const defaultPort = p.baseURL.match(/:(\d+)/)?.[1] || '';
        if (port === defaultPort) return p.baseURL;
        return `http://${ip}:${port}/v1`;
    }

    // ── HTTP helpers ─────────────────────────────────────────────────────
    async function _parseError(res, label) {
        let detail = res.statusText || 'Unknown error';
        try {
            const body = await res.json();
            detail = body?.error?.message || body?.message || body?.detail || JSON.stringify(body?.error || body) || detail;
        } catch { /**/ }
        const hint = res.status === 401 ? ' (invalid API key?)'
            : res.status === 403 ? ' (forbidden)'
            : res.status === 429 ? ' (rate limited)'
            : res.status === 404 ? ' (endpoint not found)'
            : '';
        return `${label} ${res.status}${hint}: ${detail}`;
    }

    // OpenAI-compatible /chat/completions
    async function _openaiRequest(baseURL, apiKey, model, messages, signal) {
        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
        const res = await fetch(`${baseURL}/chat/completions`, {
            method: 'POST',
            headers,
            signal,
            body: JSON.stringify({
                model,
                messages,
                max_tokens: 3000,
                temperature: 0.3,
            }),
        });
        if (!res.ok) throw new Error(await _parseError(res, 'API error'));
        const data = await res.json();
        return (data.choices?.[0]?.message?.content || '').trim();
    }

    // Anthropic Messages API
    async function _anthropicRequest(baseURL, apiKey, model, messages, signal) {
        const system = messages.find(m => m.role === 'system')?.content || '';
        const conv   = messages.filter(m => m.role !== 'system');
        const res = await fetch(`${baseURL}/messages`, {
            method: 'POST',
            signal,
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01',
                'anthropic-dangerous-direct-browser-access': 'true',
            },
            body: JSON.stringify({
                model,
                system: system || undefined,
                messages: conv,
                max_tokens: 3000,
            }),
        });
        if (!res.ok) throw new Error(await _parseError(res, 'Anthropic error'));
        const data = await res.json();
        return (data.content?.[0]?.text || '').trim();
    }

    // Google Gemini generateContent
    async function _geminiRequest(baseURL, apiKey, model, messages, signal) {
        const parts = messages.map(m => ({ text: `${m.role}: ${m.content}` }));
        const res = await fetch(
            `${baseURL}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`,
            {
                method: 'POST',
                signal,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts }],
                    generationConfig: { maxOutputTokens: 3000, temperature: 0.3 },
                }),
            }
        );
        if (!res.ok) throw new Error(await _parseError(res, 'Gemini error'));
        const data = await res.json();
        return (data.candidates?.[0]?.content?.parts?.[0]?.text || '').trim();
    }

    // Main dispatch
    async function _callAI(messages, signal) {
        const p       = PROVIDERS[_cfg.provider];
        const baseURL = _getBaseURL(_cfg.provider);
        const model   = (_cfg.model || '').trim() || p.defaultModel;
        const key     = (_cfg.apiKey || '').trim();

        switch (p.format) {
            case 'anthropic': return _anthropicRequest(baseURL, key, model, messages, signal);
            case 'gemini':    return _geminiRequest(baseURL, key, model, messages, signal);
            default:          return _openaiRequest(baseURL, key, model, messages, signal);
        }
    }

    // ── List models ──────────────────────────────────────────────────────
    async function _listModels(providerId, apiKey, localOverrideURL) {
        const p       = PROVIDERS[providerId];
        const baseURL = localOverrideURL || _getBaseURL(providerId);
        const key     = (apiKey || '').trim();

        try {
            if (p.format === 'anthropic') {
                const res = await fetch(`${baseURL}/models`, {
                    headers: { 'Content-Type': 'application/json', 'x-api-key': key,
                        'anthropic-version': '2023-06-01', 'anthropic-dangerous-direct-browser-access': 'true' },
                });
                if (!res.ok) throw new Error(await _parseError(res, 'Anthropic models'));
                const data = await res.json();
                return (data?.data || data?.models || []).map(m => m.id || m.name).filter(Boolean);
            }
            if (p.format === 'gemini') {
                const res = await fetch(`${baseURL}/models?key=${encodeURIComponent(key)}`, {
                    headers: { 'Content-Type': 'application/json' },
                });
                if (!res.ok) throw new Error(await _parseError(res, 'Gemini models'));
                const data = await res.json();
                return (data?.models || []).map(m => {
                    const n = m?.name || ''; return n.includes('/') ? n.split('/').pop() : n;
                }).filter(Boolean);
            }
            // OpenAI-compat
            const headers = { 'Accept': 'application/json' };
            if (key) headers['Authorization'] = `Bearer ${key}`;
            const res = await fetch(`${baseURL}/models`, { headers });
            if (!res.ok) throw new Error(await _parseError(res, 'Models list'));
            const data = await res.json();
            const list = Array.isArray(data) ? data : Array.isArray(data?.data) ? data.data : Array.isArray(data?.models) ? data.models : [];
            return list.map(m => m.id || m.name || (typeof m === 'string' ? m : null)).filter(Boolean);
        } catch (err) {
            throw err;
        }
    }

    function _buildRecipeContext() {
        try {
            const hasRecipe = typeof Recipe !== 'undefined' && Recipe && typeof Recipe.getSteps === 'function';
            const hasOps = typeof OperatorsRegistry !== 'undefined' && OperatorsRegistry && typeof OperatorsRegistry.getById === 'function';
            if (!hasRecipe || !hasOps) return 'Recipe context unavailable.';

            const steps = Recipe.getSteps() || [];
            const enabledSteps = steps.filter(s => !s.disabled);
            const sourceFormat = localStorage.getItem('codeswap-source-format') || 'sigma';

            if (enabledSteps.length === 0) {
                return `Source format: ${sourceFormat}\nNo active recipe steps.`;
            }

            let currentFormat = sourceFormat;
            const lines = [`Source format: ${sourceFormat}`];

            enabledSteps.forEach((step, idx) => {
                const op = OperatorsRegistry.getById(step.opId);
                if (!op) return;

                const fromFmt = op.fromFormat || currentFormat || 'unknown';
                const toFmt = op.toFormat || currentFormat || 'unknown';

                lines.push(`${idx + 1}. ${op.name} (${op.id}) ${fromFmt} -> ${toFmt}`);

                const opts = op.options || [];
                if (opts.length > 0) {
                    opts.forEach(o => {
                        const val = (step.opts && Object.prototype.hasOwnProperty.call(step.opts, o.id)) ? step.opts[o.id] : o.default;
                        if (o.type === 'checkbox') {
                            lines.push(`   - ${o.label || o.id}: ${val ? 'enabled' : 'disabled'}`);
                        } else {
                            lines.push(`   - ${o.label || o.id}: ${String(val)}`);
                        }
                    });
                }

                currentFormat = toFmt;
            });

            lines.push(`Final output format: ${currentFormat}`);
            return lines.join('\n');
        } catch {
            return 'Recipe context unavailable.';
        }
    }

    // ── Build system/user prompt ─────────────────────────────────────────
    function _buildMessages(outputText) {
        const recipeContext = _buildRecipeContext();
        const systemMsg = `You are an expert SIEM engineer and threat detection specialist with deep knowledge of Sigma rules and SIEM query languages including Splunk SPL, Elastic EQL/Lucene, Microsoft Sentinel KQL, Cortex XDR XQL, SentinelOne Deep Visibility, Carbon Black, Velociraptor VQL, IBM QRadar AQL, Chronicle UDM, and others.`;

        let userContent;
        if (_cfg.mode === 'review') {
            userContent = `Review and fix the query while preserving the intended output format and recipe/operator constraints.\n\nResponse rules:\n- Return ONLY two parts in this order:\n  1) A single fenced code block containing the final corrected query only.\n  2) A very brief explanation (1-2 sentences max).\n- Do not include section headers, bullet lists, or long analysis.\n- Apply recipe settings and option choices (including checkbox constraints such as no leading wildcards) when producing the corrected query.\n- If no changes are needed, still return the original query in the code block and then a 1-sentence confirmation.`;
        } else {
            userContent = `Explain the existing query exactly as written.\n\nResponse rules:\n- Focus on what the current query does and how it works.\n- Do not rewrite, optimize, or fix the query in Explain mode.\n- Keep the explanation concise and practical, grounded in the active recipe/output context.`;
        }

        if (_cfg.customPrompt && _cfg.customPrompt.trim()) {
            userContent += `\n\nAdditional instruction: ${_cfg.customPrompt.trim()}`;
        }

        userContent += `\n\nActive recipe and settings:\n${recipeContext}`;
        userContent += `\n\nQuery to analyze:\n\`\`\`\n${outputText}\n\`\`\``;

        return [
            { role: 'system', content: systemMsg },
            { role: 'user',   content: userContent },
        ];
    }

    // ── Validation ───────────────────────────────────────────────────────
    function _validate() {
        const p = PROVIDERS[_cfg.provider];
        if (!p) return 'Unknown provider selected.';
        if (p.requiresKey && !(_cfg.apiKey || '').trim()) {
            return `API key is required for ${p.name}.`;
        }
        if (!(_cfg.model || '').trim() && !p.defaultModel) {
            return 'Please enter a model name.';
        }
        return null;
    }

    // ── Run AI Query ─────────────────────────────────────────────────────
    async function runQuery(outputText) {
        const err = _validate();
        if (err) { _showError(err); return; }
        if (!outputText || !outputText.trim()) { _showError('No output to analyze. Run a conversion first.'); return; }

        _showResponseModal(null, true); // show loading

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 60000);

        try {
            const messages  = _buildMessages(outputText);
            let response    = await _callAI(messages, controller.signal);
            if (_cfg.mode === 'review') {
                response = _guardReviewResponse(response, outputText);
            }
            clearTimeout(timeout);
            _showResponseModal(response, false, outputText);
        } catch (err) {
            clearTimeout(timeout);
            if (err.name === 'AbortError') {
                _showResponseModal(null, false, null, 'Request timed out after 60 seconds.');
            } else {
                _showResponseModal(null, false, null, err.message || 'Unknown error');
            }
        }
    }

    // ── UI: Config Modal ─────────────────────────────────────────────────
    function openConfigModal() {
        _loadConfig();
        const overlay = document.getElementById('ai-config-overlay');
        if (!overlay) return;
        _populateConfigModal();
        overlay.style.display = 'flex';
        setTimeout(() => overlay.classList.add('visible'), 10);
    }

    function closeConfigModal() {
        const overlay = document.getElementById('ai-config-overlay');
        if (!overlay) return;
        overlay.classList.remove('visible');
        setTimeout(() => { overlay.style.display = 'none'; }, 200);
    }

    function _populateConfigModal() {
        const providerSel = document.getElementById('ai-cfg-provider');
        const modelInput  = document.getElementById('ai-cfg-model');
        const keyInput    = document.getElementById('ai-cfg-key');
        const modeExplain = document.getElementById('ai-cfg-mode-explain');
        const modeReview  = document.getElementById('ai-cfg-mode-review');
        const promptInput = document.getElementById('ai-cfg-prompt');
        const localIpInput    = document.getElementById('ai-cfg-local-ip');
        const localPortInput  = document.getElementById('ai-cfg-local-port');

        if (providerSel) {
            providerSel.innerHTML = Object.entries(PROVIDERS).map(([id, p]) =>
                `<option value="${id}"${id === _cfg.provider ? ' selected' : ''}>${p.name}</option>`
            ).join('');
        }
        if (modelInput)      modelInput.value     = _cfg.model || '';
        if (keyInput)        keyInput.value       = _cfg.apiKey || '';
        if (modeExplain)     modeExplain.checked  = _cfg.mode !== 'review';
        if (modeReview)      modeReview.checked   = _cfg.mode === 'review';
        if (promptInput)     promptInput.value    = _cfg.customPrompt || '';
        if (localIpInput)    localIpInput.value   = _cfg.localIp || 'localhost';
        if (localPortInput)  localPortInput.value = _cfg.localPort || '';

        _updateLocalVisibility();
    }

    function _updateLocalVisibility() {
        const isLocal = PROVIDERS[_cfg.provider]?.local || false;
        const localSection  = document.getElementById('ai-cfg-local-section');
        const keySection    = document.getElementById('ai-cfg-key-section');
        if (localSection) localSection.style.display = isLocal ? 'block' : 'none';
        if (keySection)   keySection.style.display   = isLocal ? 'none' : 'block';

        // Show provider-specific placeholder
        const modelInput = document.getElementById('ai-cfg-model');
        if (modelInput) {
            const p = PROVIDERS[_cfg.provider];
            modelInput.placeholder = p ? `Default: ${p.defaultModel}` : 'Model name';
        }
    }

    function _saveConfigFromModal() {
        _cfg.provider     = document.getElementById('ai-cfg-provider')?.value || 'openai';
        _cfg.model        = (document.getElementById('ai-cfg-model')?.value || '').trim();
        _cfg.apiKey       = (document.getElementById('ai-cfg-key')?.value || '').trim();
        _cfg.mode         = document.getElementById('ai-cfg-mode-review')?.checked ? 'review' : 'explain';
        _cfg.customPrompt = (document.getElementById('ai-cfg-prompt')?.value || '').trim();
        _cfg.localIp      = (document.getElementById('ai-cfg-local-ip')?.value || 'localhost').trim();
        _cfg.localPort    = (document.getElementById('ai-cfg-local-port')?.value || '').trim();
        _saveConfig();
    }

    async function _testConnection() {
        const btn       = document.getElementById('ai-cfg-test-btn');
        const statusEl  = document.getElementById('ai-cfg-test-status');
        if (!btn || !statusEl) return;

        // Read current modal values (don't save yet)
        const providerId    = document.getElementById('ai-cfg-provider')?.value || 'openai';
        const key           = (document.getElementById('ai-cfg-key')?.value || '').trim();
        const localIp       = (document.getElementById('ai-cfg-local-ip')?.value || 'localhost').trim();
        const localPort     = (document.getElementById('ai-cfg-local-port')?.value || '').trim();
        const p             = PROVIDERS[providerId];

        if (p?.requiresKey && !key) {
            statusEl.textContent = '⚠ Enter an API key first.';
            statusEl.className = 'ai-cfg-test-status warn';
            return;
        }

        btn.disabled = true;
        statusEl.textContent = 'Testing…';
        statusEl.className = 'ai-cfg-test-status info';

        let overrideURL = null;
        if (p?.local && localPort) {
            overrideURL = `http://${localIp}:${localPort}/v1`;
        }

        try {
            const models = await _listModels(providerId, key, overrideURL);
            if (models.length > 0) {
                statusEl.textContent = `✓ Connected — ${models.length} model(s) available.`;
                statusEl.className = 'ai-cfg-test-status ok';
                // Populate model datalist
                _populateModelDatalist(models);
            } else {
                statusEl.textContent = '✓ Connected (no models listed).';
                statusEl.className = 'ai-cfg-test-status ok';
            }
        } catch (err) {
            statusEl.textContent = `✗ ${err.message}`;
            statusEl.className = 'ai-cfg-test-status error';
        } finally {
            btn.disabled = false;
        }
    }

    function _populateModelDatalist(models) {
        let dl = document.getElementById('ai-model-datalist');
        if (!dl) {
            dl = document.createElement('datalist');
            dl.id = 'ai-model-datalist';
            document.body.appendChild(dl);
        }
        dl.innerHTML = models.slice(0, 100).map(m => `<option value="${m}">`).join('');
        const modelInput = document.getElementById('ai-cfg-model');
        if (modelInput) modelInput.setAttribute('list', 'ai-model-datalist');
    }

    // ── UI: Response Modal ───────────────────────────────────────────────
    function _showResponseModal(text, loading, originalOutput, errorMsg) {
        const overlay   = document.getElementById('ai-response-overlay');
        const bodyEl    = document.getElementById('ai-response-body');
        const loadEl    = document.getElementById('ai-response-loading');
        const applyBtn  = document.getElementById('ai-response-apply');
        const errEl     = document.getElementById('ai-response-error');
        const titleEl   = document.getElementById('ai-response-title');
        if (!overlay) return;

        if (titleEl) {
            titleEl.textContent = _cfg.mode === 'review' ? 'AI Review & Fix' : 'AI Explanation';
        }

        if (loading) {
            if (loadEl)  loadEl.style.display   = 'flex';
            if (bodyEl)  bodyEl.style.display   = 'none';
            if (errEl)   errEl.style.display    = 'none';
            if (applyBtn) applyBtn.style.display = 'none';
            overlay.style.display = 'flex';
            setTimeout(() => overlay.classList.add('visible'), 10);
            return;
        }

        if (loadEl) loadEl.style.display = 'none';

        if (errorMsg) {
            if (errEl)  { errEl.textContent = errorMsg; errEl.style.display = 'block'; }
            if (bodyEl) bodyEl.style.display = 'none';
            if (applyBtn) applyBtn.style.display = 'none';
        } else {
            if (errEl)  errEl.style.display = 'none';
            if (bodyEl) {
                bodyEl.style.display = 'block';
                bodyEl.innerHTML = _renderMarkdown(text || '');
            }
            // Show "Apply" button only in review mode
            if (applyBtn) {
                if (_cfg.mode === 'review') {
                    applyBtn.style.display = 'inline-flex';
                    applyBtn.dataset.response = text || '';
                } else {
                    applyBtn.style.display = 'none';
                }
            }
        }

        overlay.style.display = 'flex';
        setTimeout(() => overlay.classList.add('visible'), 10);
    }

    function closeResponseModal() {
        const overlay = document.getElementById('ai-response-overlay');
        if (!overlay) return;
        overlay.classList.remove('visible');
        setTimeout(() => { overlay.style.display = 'none'; }, 200);
    }

    // ── Very simple Markdown renderer (bold, code blocks, lists) ─────────
    function _renderMarkdown(text) {
        if (!text) return '';

        // Escape HTML first
        let html = text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        // Fenced code blocks ```lang\n...\n```
        html = html.replace(/```([^\n]*)\n([\s\S]*?)```/g, (_, lang, code) => {
            return `<pre class="ai-code-block"><code>${code.trimEnd()}</code></pre>`;
        });

        // Inline `code`
        html = html.replace(/`([^`\n]+)`/g, '<code class="ai-inline-code">$1</code>');

        // **bold**
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

        // Lines
        const lines = html.split('\n');
        const result = [];
        let inList = false;

        for (const line of lines) {
            const trimmed = line.trim();
            if (/^#{1,4}\s/.test(trimmed)) {
                if (inList) { result.push('</ul>'); inList = false; }
                const level = trimmed.match(/^(#{1,4})/)[1].length;
                const content = trimmed.replace(/^#{1,4}\s+/, '');
                result.push(`<h${Math.min(level+2,6)} class="ai-heading">${content}</h${Math.min(level+2,6)}>`);
            } else if (/^[-*•]\s/.test(trimmed) || /^\d+\.\s/.test(trimmed)) {
                if (!inList) { result.push('<ul class="ai-list">'); inList = true; }
                const content = trimmed.replace(/^[-*•]\s+|^\d+\.\s+/, '');
                result.push(`<li>${content}</li>`);
            } else {
                if (inList) { result.push('</ul>'); inList = false; }
                if (trimmed) result.push(`<p>${line}</p>`);
                else result.push('<br>');
            }
        }
        if (inList) result.push('</ul>');

        return result.join('');
    }

    // ── Extract code block from AI review response to apply ──────────────
    function _extractCodeFromResponse(text) {
        // Find the first fenced code block
        const match = text.match(/```[^\n]*\n([\s\S]*?)```/);
        return match ? match[1].trim() : null;
    }

    function _toBriefExplanation(text) {
        const clean = String(text || '')
            .replace(/```[\s\S]*?```/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();

        if (!clean) return 'Corrected query based on recipe settings and selected constraints.';

        const sentences = clean.match(/[^.!?]+[.!?]?/g) || [];
        const brief = sentences.slice(0, 2).join(' ').trim();
        if (!brief) return 'Corrected query based on recipe settings and selected constraints.';

        return brief.length > 260 ? `${brief.slice(0, 257)}...` : brief;
    }

    function _guardReviewResponse(text, originalOutput) {
        const raw = String(text || '').trim();
        const code = _extractCodeFromResponse(raw) || String(originalOutput || '').trim();
        const brief = _toBriefExplanation(raw);
        return `\`\`\`\n${code}\n\`\`\`\n\n${brief}`.trim();
    }

    function _applyReviewOutput(responseText) {
        const code = _extractCodeFromResponse(responseText);
        if (!code) {
            _showError('No corrected query code block found in the AI response.');
            return;
        }
        // Replace the output textarea content
        const outputEl = document.getElementById('output-textarea');
        const highlightEl = document.getElementById('output-highlight');
        if (outputEl) {
            outputEl.value = code;
            // Trigger update of highlight overlay if hljs is available
            if (highlightEl && typeof hljs !== 'undefined') {
                highlightEl.textContent = code;
                hljs.highlightElement(highlightEl);
            } else if (highlightEl) {
                highlightEl.textContent = code;
            }
        }
        closeResponseModal();
    }

    // ── Error snackbar ────────────────────────────────────────────────────
    function _showError(msg) {
        // Reuse the app's setStatus if available, else alert
        if (typeof App !== 'undefined' && App.setStatus) {
            App.setStatus('error', msg);
        } else {
            const sb = document.getElementById('status-bar');
            if (sb) {
                sb.className = 'status-bar status-error';
                sb.innerHTML = `<i class="bi bi-exclamation-circle"></i> ${msg}`;
            }
        }
    }

    // ── Init ─────────────────────────────────────────────────────────────
    function init() {
        _loadConfig();

        // Config modal events
        document.getElementById('ai-cfg-open')?.addEventListener('click', openConfigModal);
        document.getElementById('ai-cfg-close')?.addEventListener('click', closeConfigModal);
        document.getElementById('ai-config-overlay')?.addEventListener('click', e => {
            if (e.target === document.getElementById('ai-config-overlay')) closeConfigModal();
        });

        document.getElementById('ai-cfg-save')?.addEventListener('click', () => {
            _saveConfigFromModal();
            closeConfigModal();
        });

        document.getElementById('ai-cfg-provider')?.addEventListener('change', e => {
            _cfg.provider = e.target.value;
            _updateLocalVisibility();
        });

        document.getElementById('ai-cfg-test-btn')?.addEventListener('click', _testConnection);

        // AI query button
        document.getElementById('btn-ai-query')?.addEventListener('click', () => {
            const outputEl = document.getElementById('output-textarea');
            const text = outputEl?.value?.trim();
            runQuery(text || '');
        });

        // Response modal events
        document.getElementById('ai-response-close')?.addEventListener('click', closeResponseModal);
        document.getElementById('ai-response-overlay')?.addEventListener('click', e => {
            if (e.target === document.getElementById('ai-response-overlay')) closeResponseModal();
        });

        document.getElementById('ai-response-copy')?.addEventListener('click', () => {
            const bodyEl = document.getElementById('ai-response-body');
            const text   = bodyEl?.innerText || '';
            navigator.clipboard.writeText(text).catch(() => { /**/ });
            const btn = document.getElementById('ai-response-copy');
            if (btn) { btn.innerHTML = '<i class="bi bi-check-lg"></i> Copied'; setTimeout(() => { btn.innerHTML = '<i class="bi bi-clipboard"></i> Copy'; }, 1500); }
        });

        document.getElementById('ai-response-apply')?.addEventListener('click', e => {
            const responseText = e.currentTarget.dataset.response || '';
            _applyReviewOutput(responseText);
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') {
                closeConfigModal();
                closeResponseModal();
            }
        });
    }

    return { init, openConfigModal, closeConfigModal, runQuery };
})();
