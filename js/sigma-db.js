/**
 * sigma-db.js
 * Sigma Rules Database — Downloads SigmaHQ rules from GitHub,
 * parses to JSON, stores in IndexedDB, and provides search.
 */
'use strict';

const SigmaDB = (() => {

    const DB_NAME    = 'codeswap-sigma-db';
    const DB_VERSION = 1;
    const STORE_NAME = 'rules';
    const META_STORE = 'meta';

    const GITHUB_TREE_API = 'https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1';
    const RAW_BASE        = 'https://raw.githubusercontent.com/SigmaHQ/sigma/master/';

    // Concurrent fetch limit to avoid hammering GitHub
    const CONCURRENCY = 8;

    let _db = null;

    // ── IndexedDB open ──────────────────────────────────────────────────
    function openDB() {
        if (_db) return Promise.resolve(_db);

        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, DB_VERSION);

            req.onupgradeneeded = e => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    const store = db.createObjectStore(STORE_NAME, { keyPath: 'path' });
                    store.createIndex('title', 'title', { unique: false });
                    store.createIndex('category', 'category', { unique: false });
                }
                if (!db.objectStoreNames.contains(META_STORE)) {
                    db.createObjectStore(META_STORE);
                }
            };

            req.onsuccess = e => { _db = e.target.result; resolve(_db); };
            req.onerror   = e => reject(e.target.error);
        });
    }

    function txStore(db, storeName, mode) {
        return db.transaction([storeName], mode).objectStore(storeName);
    }

    function idbPut(store, key, value) {
        return new Promise((res, rej) => {
            const req = typeof key === 'undefined' ? store.put(value) : store.put(value, key);
            req.onsuccess = () => res();
            req.onerror   = e => rej(e.target.error);
        });
    }

    function idbGet(store, key) {
        return new Promise((res, rej) => {
            const req = store.get(key);
            req.onsuccess = e => res(e.target.result);
            req.onerror   = e => rej(e.target.error);
        });
    }

    function idbGetAll(store) {
        return new Promise((res, rej) => {
            const req = store.getAll();
            req.onsuccess = e => res(e.target.result);
            req.onerror   = e => rej(e.target.error);
        });
    }

    function idbClearStore(store) {
        return new Promise((res, rej) => {
            const req = store.clear();
            req.onsuccess = () => res();
            req.onerror   = e => rej(e.target.error);
        });
    }

    function idbCount(store) {
        return new Promise((res, rej) => {
            const req = store.count();
            req.onsuccess = e => res(e.target.result);
            req.onerror   = e => rej(e.target.error);
        });
    }

    // ── Download ────────────────────────────────────────────────────────

    /**
     * Download all Sigma rules from SigmaHQ/sigma on GitHub.
     * Calls onProgress({ done, total, phase, error? }) periodically.
     * Overwrites existing cache.
     */
    async function download(onProgress) {
        onProgress({ phase: 'tree', done: 0, total: 0 });

        // Step 1: fetch git tree
        let treeResp;
        try {
            treeResp = await fetch(GITHUB_TREE_API);
        } catch (e) {
            throw new Error(`Network error fetching rule list: ${e.message}`);
        }

        if (!treeResp.ok) {
            throw new Error(`GitHub API error ${treeResp.status}: ${treeResp.statusText}`);
        }

        const treeData = await treeResp.json();

        if (treeData.truncated) {
            console.warn('SigmaDB: GitHub tree response was truncated — some rules may be missing.');
        }

        // Filter to .yml files under rules/ directory only
        const rulePaths = (treeData.tree || [])
            .filter(item => item.type === 'blob' && item.path.startsWith('rules/') && item.path.endsWith('.yml'))
            .map(item => item.path);

        const total = rulePaths.length;

        if (total === 0) {
            throw new Error('No rule files found in SigmaHQ/sigma repository tree.');
        }

        onProgress({ phase: 'download', done: 0, total });

        // Step 2: open DB and clear existing rules
        const db = await openDB();
        const clearTx = db.transaction([STORE_NAME, META_STORE], 'readwrite');
        await idbClearStore(clearTx.objectStore(STORE_NAME));
        await new Promise(r => { clearTx.oncomplete = r; clearTx.onerror = r; });

        // Step 3: fetch each rule file with bounded concurrency
        let done = 0;
        let errorCount = 0;

        async function fetchRule(path) {
            try {
                const resp = await fetch(RAW_BASE + path);
                if (!resp.ok) { errorCount++; return null; }
                const yaml = await resp.text();
                const parsed = parseRuleYaml(yaml, path);
                return parsed;
            } catch {
                errorCount++;
                return null;
            }
        }

        // Process in batches
        const parsedRules = [];
        for (let i = 0; i < rulePaths.length; i += CONCURRENCY) {
            const batch = rulePaths.slice(i, i + CONCURRENCY);
            const results = await Promise.all(batch.map(fetchRule));
            for (const r of results) {
                if (r) parsedRules.push(r);
            }
            done += batch.length;
            onProgress({ phase: 'download', done, total, errorCount });
        }

        // Step 4: bulk-write to IndexedDB
        onProgress({ phase: 'saving', done: parsedRules.length, total: parsedRules.length });

        const writeTx = db.transaction([STORE_NAME, META_STORE], 'readwrite');
        const ruleStore = writeTx.objectStore(STORE_NAME);
        const metaStore = writeTx.objectStore(META_STORE);

        for (const rule of parsedRules) {
            ruleStore.put(rule);
        }

        const now = new Date().toISOString();
        metaStore.put({ count: parsedRules.length, updatedAt: now, errorCount }, 'info');

        await new Promise((res, rej) => {
            writeTx.oncomplete = res;
            writeTx.onerror    = e => rej(e.target.error);
        });

        onProgress({ phase: 'done', done: parsedRules.length, total, errorCount });

        return { count: parsedRules.length, errorCount };
    }

    // ── YAML parser (minimal — extracts key fields from Sigma rule YAML) ─
    function parseRuleYaml(yamlText, path) {
        // Use js-yaml if available, otherwise fall back to regex extraction
        let doc = null;

        if (typeof jsyaml !== 'undefined') {
            try { doc = jsyaml.load(yamlText); } catch { doc = null; }
        }

        const parts = path.split('/');
        // path like: rules/windows/process_creation/proc_creation_win_...yml
        const category = parts.length >= 3 ? parts[1] : 'other';
        const subcategory = parts.length >= 4 ? parts[2] : '';

        if (doc && typeof doc === 'object') {
            return {
                path,
                title:       String(doc.title || '').trim(),
                id:          String(doc.id || '').trim(),
                status:      String(doc.status || '').trim(),
                description: String(doc.description || '').trim(),
                level:       String(doc.level || '').trim(),
                tags:        Array.isArray(doc.tags) ? doc.tags.map(String) : [],
                author:      String(doc.author || '').trim(),
                category,
                subcategory,
                raw:         yamlText,
            };
        }

        // Fallback: regex extraction
        const get = (key) => {
            const m = yamlText.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'));
            return m ? m[1].replace(/^['"]|['"]$/g, '').trim() : '';
        };
        const tagsM = yamlText.match(/^tags:\s*\n((?:\s+-\s*.+\n?)+)/m);
        const tags  = tagsM
            ? tagsM[1].split('\n').map(l => l.replace(/^\s+-\s*/, '').trim()).filter(Boolean)
            : [];

        return {
            path,
            title:       get('title'),
            id:          get('id'),
            status:      get('status'),
            description: get('description'),
            level:       get('level'),
            tags,
            author:      get('author'),
            category,
            subcategory,
            raw:         yamlText,
        };
    }

    // ── Search ──────────────────────────────────────────────────────────

    /**
     * Search stored rules.
     * Returns up to `limit` matching rule records (metadata only, raw included).
     */
    async function search(query, limit = 200) {
        const db = await openDB();
        const store = txStore(db, STORE_NAME, 'readonly');
        const all   = await idbGetAll(store);

        if (!query || !query.trim()) {
            return all.slice(0, limit);
        }

        const q = query.toLowerCase().trim();
        const terms = q.split(/\s+/);

        const scored = [];
        for (const rule of all) {
            const haystack = [
                rule.title,
                rule.description,
                rule.category,
                rule.subcategory,
                rule.level,
                rule.author,
                ...(rule.tags || []),
            ].join(' ').toLowerCase();

            let score = 0;
            for (const term of terms) {
                if (haystack.includes(term)) score++;
                if ((rule.title || '').toLowerCase().includes(term)) score += 2;
            }

            if (score > 0) scored.push({ score, rule });
        }

        scored.sort((a, b) => b.score - a.score);
        return scored.slice(0, limit).map(s => s.rule);
    }

    // ── Meta ────────────────────────────────────────────────────────────

    async function getMeta() {
        try {
            const db    = await openDB();
            const store = txStore(db, META_STORE, 'readonly');
            return await idbGet(store, 'info');
        } catch {
            return null;
        }
    }

    async function getCount() {
        try {
            const db    = await openDB();
            const store = txStore(db, STORE_NAME, 'readonly');
            return await idbCount(store);
        } catch {
            return 0;
        }
    }

    async function reset() {
        if (_db) {
            try { _db.close(); } catch {}
            _db = null;
        }

        await new Promise((resolve, reject) => {
            const req = indexedDB.deleteDatabase(DB_NAME);
            req.onsuccess = () => resolve();
            req.onerror = e => reject(e.target.error || new Error('Failed to delete Sigma DB.'));
            req.onblocked = () => reject(new Error('Reset blocked. Close other QueryCast tabs and try again.'));
        });
    }

    // ── Public API ──────────────────────────────────────────────────────
    return { download, search, getMeta, getCount, reset };

})();
