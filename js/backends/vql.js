/**
 * vql.js
 * Sigma → Velociraptor VQL backend
 *
 * Produces VQL (Velociraptor Query Language) SELECT statements for
 * incident response and forensic artifact collection.
 *
 * References:
 *   https://docs.velociraptor.app/docs/vql/
 *   Velociraptor VQL skill
 */
'use strict';

class VqlBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        // Options: { addComments: true, limit: 1000 }
        this.addComments = options.addComments !== false;
        this.limit = options.limit || 1000;
    }

    // ── Override main convert ──────────────────────────────────────────
    convert(sigmaRule) {
        // Reset per-conversion tracking (same as base-backend)
        this._skippedFields = [];

        const header  = this.buildHeader(sigmaRule);
        const body    = this._buildVqlQuery(sigmaRule);
        const footer  = this.buildFooter(sigmaRule);

        let warning = '';
        if (this._skippedFields.length > 0) {
            const unique = [...new Set(this._skippedFields)];
            const bodyEmpty = !body || !body.trim();
            if (bodyEmpty) {
                warning = `-- ⚠️ WARNING: All detection filters were removed — ` +
                    `the following fields are not supported for VQL: ${unique.join(', ')}. ` +
                    `No conditions remain in the output.`;
            } else {
                warning = `-- ⚠️ Note: ${unique.length} field(s) not supported for VQL ` +
                    `and were removed: ${unique.join(', ')}`;
            }
        }

        return [warning, header, body, footer].filter(p => p && p.trim()).join('\n');
    }

    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [];
        if (sigmaRule.title)       lines.push(`-- Title: ${sigmaRule.title}`);
        if (sigmaRule.level)       lines.push(`-- Level: ${sigmaRule.level}`);
        if (sigmaRule.description) lines.push(`-- Description: ${sigmaRule.description.split('\n')[0]}`);
        lines.push(`-- Backend: Velociraptor VQL`);
        return lines.join('\n');
    }

    // ── Build the complete VQL SELECT statement ──────────────────────
    _buildVqlQuery(sigmaRule) {
        const artifact = FieldMaps.getVqlArtifact(sigmaRule.logsource);
        const fromClause = artifact
            ? `FROM ${artifact}`
            : `FROM Artifact.Generic.Events  -- Unknown logsource: manually specify artifact`;

        const whereExpr = this._conditionToVql(sigmaRule.detection.conditionAst, sigmaRule);

        const lines = [
            'SELECT *',
            fromClause,
        ];

        if (whereExpr && whereExpr.trim()) {
            lines.push(`WHERE ${whereExpr}`);
        }

        lines.push(`LIMIT ${this.limit}`);

        return lines.join('\n');
    }

    // ── Condition AST → VQL WHERE expression ─────────────────────────
    _conditionToVql(node, sigmaRule) {
        switch (node.type) {
            case 'ref': {
                const key = Object.keys(sigmaRule.detection.identifiers)
                    .find(k => k.toLowerCase() === node.name.toLowerCase());
                if (!key) return `/* unknown: ${node.name} */`;
                return this._identifierToVql(sigmaRule.detection.identifiers[key], sigmaRule);
            }
            case 'and': {
                const l = this._conditionToVql(node.left, sigmaRule);
                const r = this._conditionToVql(node.right, sigmaRule);
                if (!l && !r) return '';
                if (!l) return r;
                if (!r) return l;
                return `(${l}\n  AND ${r})`;
            }
            case 'or': {
                const l = this._conditionToVql(node.left, sigmaRule);
                const r = this._conditionToVql(node.right, sigmaRule);
                if (!l && !r) return '';
                if (!l) return r;
                if (!r) return l;
                return `(${l}\n  OR ${r})`;
            }
            case 'not': {
                const inner = this._conditionToVql(node.expr, sigmaRule);
                if (!inner) return '';
                return `NOT (${inner})`;
            }
            case 'all_of': {
                const parts = node.identifiers.map(id => {
                    const k = Object.keys(sigmaRule.detection.identifiers)
                        .find(k2 => k2.toLowerCase() === id.toLowerCase());
                    return this._identifierToVql(sigmaRule.detection.identifiers[k], sigmaRule);
                }).filter(Boolean);
                if (parts.length === 0) return '';
                return parts.reduce((a, b) => `(${a} AND ${b})`);
            }
            case 'any_of': {
                const parts = node.identifiers.map(id => {
                    const k = Object.keys(sigmaRule.detection.identifiers)
                        .find(k2 => k2.toLowerCase() === id.toLowerCase());
                    return this._identifierToVql(sigmaRule.detection.identifiers[k], sigmaRule);
                }).filter(Boolean);
                if (parts.length === 0) return '';
                return parts.reduce((a, b) => `(${a} OR ${b})`);
            }
            default: return `/* unknown: ${node.type} */`;
        }
    }

    _identifierToVql(node, sigmaRule) {
        if (!node) return '';
        switch (node.type) {
            case 'field_condition': {
                const result = this.buildFieldCondition(node, sigmaRule.logsource);
                if (!result) {
                    // Field not supported – track it for the warning
                    this._skippedFields = this._skippedFields || [];
                    this._skippedFields.push(node.field);
                    return '';
                }
                return result;
            }
            case 'and_conditions': {
                const parts = node.conditions.map(c => this._identifierToVql(c, sigmaRule)).filter(Boolean);
                return parts.length === 1 ? parts[0] : `(${parts.join('\n  AND ')})`;
            }
            case 'or_conditions': {
                const parts = node.conditions.map(c => this._identifierToVql(c, sigmaRule)).filter(Boolean);
                return parts.length === 1 ? parts[0] : `(${parts.join('\n  OR ')})`;
            }
            case 'keywords':
                return this.buildKeywords(node.values, sigmaRule.logsource);
            default: return `/* unknown: ${node.type} */`;
        }
    }

    // ── Field mapping ──────────────────────────────────────────────
    _mapField(fieldName, logsource) {
        return FieldMaps.mapField(fieldName, logsource, 'vql', true);
    }

    // ── Build a complete field condition ────────────────────────────
    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // unsupported – caller tracks and skips

        // Null value → field IS NULL
        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField} = NULL`;
        }

        const [primaryMod] = node.modifiers;

        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers));

        if (node.useAll) {
            return parts.reduce((a, b) => `(${a} AND ${b})`);
        }

        if (parts.length === 1) return parts[0];
        return `(${parts.join('\n  OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        // VQL uses =~ for regex (Go-style)
        if (primaryMod === 're' || primaryMod === 'regex') {
            return `${field} =~ '(?i)${this._escapeVqlRegex(value)}'`;
        }

        // CIDR – VQL doesn't have built-in CIDR; use string contains
        if (primaryMod === 'cidr') {
            const [ip, prefix] = value.split('/');
            const networkPrefix = ip.split('.').slice(0, Math.ceil(parseInt(prefix) / 8)).join('.');
            return `${field} =~ '${networkPrefix}'`;
        }

        // Base64
        if (allMods.includes('base64') || allMods.includes('base64offset')) {
            try {
                const decoded = atob(value);
                return `${field} =~ '(?i)${this._escapeVqlRegex(decoded)}'`;
            } catch {
                return `${field} =~ '(?i)${this._escapeVqlRegex(value)}'`;
            }
        }

        switch (primaryMod) {
            case 'contains': {
                const escaped = this._escapeVqlRegex(value);
                return `${field} =~ '(?i).*${escaped}.*'`;
            }
            case 'startswith': {
                const escaped = this._escapeVqlRegex(value);
                return `${field} =~ '(?i)${escaped}.*'`;
            }
            case 'endswith': {
                const escaped = this._escapeVqlRegex(value);
                return `${field} =~ '(?i).*${escaped}$'`;
            }
            case 'equals':
            case undefined:
            case null:
            case '':
                if (value === null || value === '') return `${field} = NULL`;
                if (value.includes('*') || value.includes('?')) {
                    const regexPart = this._globToRegex(value);
                    return `${field} =~ '(?i)${regexPart}'`;
                }
                return `${field} = '${this._escapeVqlString(value)}'`;
            default:
                return `${field} = '${this._escapeVqlString(value)}'`;
        }
    }

    _escapeVqlString(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'");
    }

    _escapeVqlRegex(value) {
        if (value === null || value === undefined) return '';
        // Escape special regex chars except . which is likely intentional as .
        return String(value)
            .replace(/\\/g, '\\\\')
            .replace(/([+*?^${}()|[\]])/g, '\\$1')
            .replace(/'/g, "\\'");
    }

    _globToRegex(glob) {
        return glob
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.');
    }

    // ── Keyword search ─────────────────────────────────────────────────
    buildKeywords(values, logsource) {
        // VQL: search for keywords in all string fields using regex
        const clauses = values.map(v => `log_message =~ '(?i)${this._escapeVqlRegex(v)}'`);
        return clauses.length === 1 ? clauses[0] : `(${clauses.join('\n  OR ')})`;
    }

    andExpr(a, b)  { return `(${a} AND ${b})`; }
    orExpr(a, b)   { return `(${a} OR ${b})`; }
    notExpr(a)     { return `NOT (${a})`; }
    wrapGroup(a)   { return `(${a})`; }

    // base backend compat stubs (not used directly in this override)
    buildFieldConditionStub(node, logsource) { return this.buildFieldCondition(node, logsource); }

    // ── Reverse parser: VQL → Sigma ───────────────────────────────────
    static parseQueryToSigma(vqlQuery) {
        if (!vqlQuery || typeof vqlQuery !== 'string') return '';

        try {
            const comparisons = this._parseVqlComparisons(vqlQuery);
            if (!comparisons.length) {
                return this._buildSigmaKeywords(vqlQuery);
            }

            const detections = this._extractSigmaDetections(comparisons);
            return this._buildSigmaYAML(detections);
        } catch (_err) {
            return this._buildSigmaKeywords(vqlQuery);
        }
    }

    static _buildVqlInverseMap() {
        const inverse = {};
        const tables = [
            FieldMaps.PROCESS_CREATION,
            FieldMaps.NETWORK_CONNECTION,
            FieldMaps.FILE_EVENT,
            FieldMaps.REGISTRY_EVENT,
            FieldMaps.WINDOWS_SECURITY,
            FieldMaps.DNS_QUERY,
            FieldMaps.IMAGE_LOAD,
        ];

        tables.forEach(table => {
            Object.entries(table || {}).forEach(([sigmaField, backendMap]) => {
                if (!backendMap) return;
                const vql = backendMap.vql;
                if (vql && !inverse[vql]) inverse[vql] = sigmaField;
            });
        });

        const byLower = {};
        Object.entries(inverse).forEach(([k, v]) => {
            byLower[k.toLowerCase()] = v;
        });

        return { byExact: inverse, byLower };
    }

    static _mapVqlFieldToSigma(fieldName) {
        if (!this._vqlInverseMapCache) {
            this._vqlInverseMapCache = this._buildVqlInverseMap();
        }

        const raw = String(fieldName || '').trim();
        if (!raw) return raw;

        return this._vqlInverseMapCache.byExact[raw]
            || this._vqlInverseMapCache.byLower[raw.toLowerCase()]
            || raw;
    }

    static _stripQuoted(valueRaw) {
        let v = String(valueRaw || '').trim();
        if (v.startsWith('@')) v = v.slice(1).trim();
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.slice(1, -1);
        }
        return this._normalizeParsedVqlValue(v.replace(/\\'/g, "'").replace(/\\"/g, '"'));
    }

    static _normalizeParsedVqlValue(value) {
        if (value === null || value === undefined) return '';

        return String(value)
            // VQL-encoded path separators / escaped backslashes.
            .replace(/\\\\/g, '\\')
            // Escaped regex punctuation that originated from literal Sigma values.
            .replace(/\\([+*?^${}()|\[\]\\.])/g, '$1');
    }

    static _parseVqlComparisons(vqlQuery) {
        const withoutComments = String(vqlQuery || '')
            .split('\n')
            .map(line => line.replace(/--.*$/, ''))
            .join('\n')
            .trim();

        if (!withoutComments) return [];

        const whereMatch = withoutComments.match(/\bwhere\b/i);
        let conditionText = whereMatch ? withoutComments.slice(whereMatch.index + whereMatch[0].length) : withoutComments;
        conditionText = conditionText
            .split(/\blimit\b/i)[0]
            .trim();

        const comparisons = [];

        const rxRegex = /\b(not\s+)?([A-Za-z_][\w.]*)\s*(=~|!~)\s*'((?:\\.|[^'])*)'/gi;
        let m;
        while ((m = rxRegex.exec(conditionText)) !== null) {
            const prefNot = Boolean(m[1]);
            const field = this._mapVqlFieldToSigma(m[2]);
            const opNeg = m[3] === '!~';
            const negated = prefNot ? !opNeg : opNeg;
            const pattern = String(m[4] || '');

            let op = 'matches regex';
            let value = pattern;

            const containsMatch = pattern.match(/^\(\?i\)\.\*(.*)\.\*$/);
            const startsWithMatch = pattern.match(/^\(\?i\)([^.*].*)\.\*$/);
            const endsWithMatch = pattern.match(/^\(\?i\)\.\*(.*)\$$/);
            const exactCiMatch = pattern.match(/^\(\?i\)(.*)$/);

            if (containsMatch) {
                op = 'contains';
                value = this._normalizeParsedVqlValue(containsMatch[1]);
            } else if (startsWithMatch) {
                op = 'startswith';
                value = this._normalizeParsedVqlValue(startsWithMatch[1]);
            } else if (endsWithMatch) {
                op = 'endswith';
                value = this._normalizeParsedVqlValue(endsWithMatch[1]);
            } else if (exactCiMatch) {
                op = 'equals';
                value = this._normalizeParsedVqlValue(exactCiMatch[1]);
            } else {
                value = this._normalizeParsedVqlValue(value);
            }

            comparisons.push({ field, value, op, negated });
        }

        // Match plain equality/inequality only (exclude regex operator '=~').
        const rxEq = /\b(not\s+)?([A-Za-z_][\w.]*)\s*(!=|=(?!~))\s*(@?'(?:\\.|[^'])*'|@?"(?:\\.|[^"])*"|[^\s)]+)/gi;
        while ((m = rxEq.exec(conditionText)) !== null) {
            const prefNot = Boolean(m[1]);
            const field = this._mapVqlFieldToSigma(m[2]);
            const opRaw = m[3];
            const opNeg = opRaw === '!=';
            const negated = prefNot ? !opNeg : opNeg;

            comparisons.push({
                field,
                value: this._stripQuoted(m[4]),
                op: 'equals',
                negated,
            });
        }

        return this._dedupeComparisons(comparisons);
    }

    static _dedupeComparisons(comparisons) {
        const seen = new Set();
        const out = [];

        comparisons.forEach(comp => {
            if (!comp || !comp.field) return;
            const value = comp.value == null ? '' : String(comp.value);
            const key = `${comp.field}::${comp.op}::${comp.negated ? '1' : '0'}::${value}`;
            if (seen.has(key)) return;
            seen.add(key);
            out.push(comp);
        });

        return out;
    }

    static _extractSigmaDetections(comparisons) {
        const detections = {
            selection: {},
            filter_blocks: {},
            conditions: ['selection'],
        };

        comparisons.forEach(comp => {
            let modifier = '';
            if (comp.op === 'contains') modifier = '|contains';
            else if (comp.op === 'startswith') modifier = '|startswith';
            else if (comp.op === 'endswith') modifier = '|endswith';
            else if (comp.op === 'matches regex') modifier = '|re';

            const fieldKey = modifier ? `${comp.field}${modifier}` : comp.field;

            if (!comp.negated) {
                detections.selection[fieldKey] = detections.selection[fieldKey] || [];
                detections.selection[fieldKey].push(comp.value);
                return;
            }

            const baseName = `filter_${String(comp.field).replace(/[^A-Za-z0-9_]/g, '_')}`;
            detections.filter_blocks[baseName] = detections.filter_blocks[baseName] || {};
            detections.filter_blocks[baseName][fieldKey] = detections.filter_blocks[baseName][fieldKey] || [];
            detections.filter_blocks[baseName][fieldKey].push(comp.value);
        });

        const filterNames = Object.keys(detections.filter_blocks);
        if (filterNames.length > 0) {
            const filterExpr = filterNames.length === 1
                ? filterNames[0]
                : `(${filterNames.join(' or ')})`;
            detections.conditions.push(`not ${filterExpr}`);
        }

        return detections;
    }

    static _buildSigmaYAML(detections) {
        const lines = [
            'title: Imported VQL Query',
            'description: Converted from Velociraptor VQL query',
            'logsource:',
            '  product: windows',
            '  category: process_creation',
            'detection:',
        ];

        if (Object.keys(detections.selection).length) {
            lines.push('  selection:');
            for (const [key, values] of Object.entries(detections.selection)) {
                if (values.length === 1) {
                    lines.push(`    ${key}: '${String(values[0]).replace(/'/g, "''")}'`);
                } else {
                    lines.push(`    ${key}:`);
                    values.forEach(v => lines.push(`      - '${String(v).replace(/'/g, "''")}'`));
                }
            }
        }

        for (const [filterName, block] of Object.entries(detections.filter_blocks)) {
            lines.push(`  ${filterName}:`);
            for (const [key, values] of Object.entries(block)) {
                if (values.length === 1) {
                    lines.push(`    ${key}: '${String(values[0]).replace(/'/g, "''")}'`);
                } else {
                    lines.push(`    ${key}:`);
                    values.forEach(v => lines.push(`      - '${String(v).replace(/'/g, "''")}'`));
                }
            }
        }

        lines.push(`  condition: ${detections.conditions.join(' and ')}`);
        return lines.join('\n');
    }

    static _buildSigmaKeywords(raw) {
        const trimmed = String(raw || '').trim().replace(/'/g, "''");
        return [
            'title: Imported VQL Query',
            'description: Converted from Velociraptor VQL query',
            'logsource:',
            '  product: windows',
            '  category: process_creation',
            'detection:',
            '  keywords:',
            `    - '${trimmed}'`,
            '  condition: keywords',
        ].join('\n');
    }
}
