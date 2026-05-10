/**
 * kql.js
 * Sigma → Microsoft KQL backend
 *
 * Produces KQL queries for:
 *   - Microsoft Sentinel (Log Analytics Workspace)
 *   - Microsoft Defender for Endpoint (Advanced Hunting)
 *
 * References:
 *   https://github.com/SigmaHQ/pySigma-backend-microsoft365defender
 *   https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/
 *   https://learn.microsoft.com/en-us/azure/sentinel/kusto-overview
 */
'use strict';

class KqlBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        // Options: { platform: 'sentinel' | 'defender', addComments: true }
        this.platform    = options.platform || 'sentinel';
        this.addComments = options.addComments !== false;
    }

    // ── Logsource header: KQL table + where clauses ────────────────────
    buildHeader(sigmaRule) {
        const useDefender = this.platform === 'defender';
        const table = FieldMaps.getKqlTable(sigmaRule.logsource, useDefender);

        const commentLines = [];
        if (this.addComments) {
            if (sigmaRule.title)       commentLines.push(`// Title: ${sigmaRule.title}`);
            if (sigmaRule.level)       commentLines.push(`// Level: ${sigmaRule.level}`);
            if (sigmaRule.description) commentLines.push(`// Description: ${sigmaRule.description.split('\n')[0]}`);
        }

        const commentBlock = commentLines.length > 0 ? commentLines.join('\n') + '\n' : '';

        if (table) {
            return commentBlock + table;
        }

        // Unknown logsource – emit a raw table placeholder
        const ls = sigmaRule.logsource;
        const placeholder = ls.product ? `${ls.product}_logs` : 'Events';
        return commentBlock + `${placeholder}  // Unknown logsource: manually specify table`;
    }

    // ── Field mapping ──────────────────────────────────────────────────
    _mapField(fieldName, logsource) {
        const backend = this.platform === 'defender' ? 'kql_dev' : 'kql_sec';
        const mapped = FieldMaps.mapField(fieldName, logsource, backend, true);
        // If the primary backend returned null, try the other KQL variant as fallback
        if (mapped === null) {
            const alt = FieldMaps.mapField(fieldName, logsource, backend === 'kql_dev' ? 'kql_sec' : 'kql_dev', true);
            if (alt !== null) return alt;
        }
        return mapped; // null → field not supported in either KQL variant
    }

    // ── Build a complete field condition ──────────────────────────────
    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // unsupported field – caller will skip and warn

        // Null value → field is empty check
        if (node.values.length === 1 && node.values[0] === null) {
            return `isempty(${mappedField})`;
        }

        const [primaryMod] = node.modifiers;

        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers));

        if (node.useAll) {
            const combined = parts.reduce((a, b) => this.andExpr(a, b));
            return parts.length > 1 ? `(${combined})` : combined;
        }

        // For single values, keep simple; multiple values → has_any when possible
        if (parts.length === 1) return parts[0];

        // Optimise: if all parts use same operator on same field, use has_any / in~
        const canOptimise = this._canOptimise(node, primaryMod);
        if (canOptimise) {
            return this._buildOptimised(mappedField, node.values, primaryMod);
        }

        return `(${parts.join(' or ')})`;
    }

    _canOptimise(node, primaryMod) {
        // Only optimise simple single-modifier list conditions
        if (node.useAll) return false;
        if (node.values.some(v => v === null || v === undefined)) return false;
        return ['contains', 'startswith', 'endswith', 'equals', '', undefined, null].includes(primaryMod);
    }

    _buildOptimised(field, values, primaryMod) {
        const quoted = values.map(v => `'${this._escapeKqlString(v)}'`).join(', ');
        switch (primaryMod) {
            case 'contains':
                if (values.length > 1) return `${field} has_any (${quoted})`;
                return `${field} contains '${this._escapeKqlString(values[0])}'`;
            case 'startswith':
                if (values.length > 1) return `(${values.map(v => `${field} startswith '${this._escapeKqlString(v)}'`).join(' or ')})`;
                return `${field} startswith '${this._escapeKqlString(values[0])}'`;
            case 'endswith':
                if (values.length > 1) return `(${values.map(v => `${field} endswith '${this._escapeKqlString(v)}'`).join(' or ')})`;
                return `${field} endswith '${this._escapeKqlString(values[0])}'`;
            case 'equals':
            case undefined:
            case null:
            case '':
                if (values.length > 1) return `${field} in~ (${quoted})`;
                return `${field} == '${this._escapeKqlString(values[0])}'`;
        }
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        // Regex
        if (primaryMod === 're' || primaryMod === 'regex') {
            return `${field} matches regex @'${this._escapeKqlRegex(value)}'`;
        }

        // CIDR
        if (primaryMod === 'cidr') {
            return `ipv4_is_in_range(${field}, '${value}')`;
        }

        // Base64
        if (allMods.includes('base64') || allMods.includes('base64offset')) {
            try {
                const decoded = atob(value);
                return `${field} contains '${this._escapeKqlString(decoded)}'`;
            } catch {
                return `${field} contains '${this._escapeKqlString(value)}'`;
            }
        }

        const escaped = this._escapeKqlString(value);

        switch (primaryMod) {
            case 'contains':    return `${field} contains '${escaped}'`;
            case 'startswith':  return `${field} startswith '${escaped}'`;
            case 'endswith':    return `${field} endswith '${escaped}'`;
            case 'equals':
            case undefined:
            case null:
            case '':
                if (value === null || value === '') return `isempty(${field})`;
                if (value.includes('*') || value.includes('?')) {
                    // Convert glob to KQL wildcard
                    return `${field} matches regex @'${this._globToRegex(value)}'`;
                }
                return `${field} =~ '${escaped}'`;
            default:
                return `${field} =~ '${escaped}'`;
        }
    }

    _escapeKqlString(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'");
    }

    _escapeKqlRegex(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/'/g, "\\'");
    }

    _globToRegex(glob) {
        return glob
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.');
    }

    // ── Keyword search ─────────────────────────────────────────────────
    buildKeywords(values, logsource) {
        // KQL doesn't have a true full-text keyword search across all fields.
        // Emit a search-like expression or a comment noting manual review needed.
        if (values.length === 1) {
            return `* contains '${this._escapeKqlString(values[0])}'`;
        }
        const clauses = values.map(v => `* contains '${this._escapeKqlString(v)}'`);
        return `(${clauses.join(' or ')})`;
    }

    // ── Logical operators ──────────────────────────────────────────────
    andExpr(a, b)  {
        // Wrap multi-line a/b in parens for clarity
        return `${a}\n| where ${b}`;
    }

    orExpr(a, b)   { return `(${a} or ${b})`; }
    notExpr(a)     { return `not (${a})`; }
    wrapGroup(a)   { return `(${a})`; }

    // ── Override to produce pipe-based KQL output ──────────────────────
    convert(sigmaRule) {
        const header = this.buildHeader(sigmaRule);
        const body   = this._buildWhereClause(sigmaRule);
        const footer = this.buildFooter(sigmaRule);

        const parts = [header, body, footer].filter(p => p && p.trim() !== '');
        return parts.join('\n');
    }

    _buildWhereClause(sigmaRule) {
        const condStr = this._conditionToKql(sigmaRule.detection.conditionAst, sigmaRule);
        if (!condStr || condStr.trim() === '') return '';
        return `| where ${condStr}`;
    }

    // Re-implement the AST walker to produce flat KQL expressions (not pipe-chained)
    _conditionToKql(node, sigmaRule) {
        switch (node.type) {
            case 'ref': {
                const key = Object.keys(sigmaRule.detection.identifiers)
                    .find(k => k.toLowerCase() === node.name.toLowerCase());
                if (!key) return `/* unknown identifier: ${node.name} */`;
                const idNode = sigmaRule.detection.identifiers[key];
                return this._identifierToKql(idNode, sigmaRule);
            }
            case 'and': {
                const l = this._conditionToKql(node.left, sigmaRule);
                const r = this._conditionToKql(node.right, sigmaRule);
                return `(${l} and ${r})`;
            }
            case 'or': {
                const l = this._conditionToKql(node.left, sigmaRule);
                const r = this._conditionToKql(node.right, sigmaRule);
                return `(${l} or ${r})`;
            }
            case 'not': {
                const inner = this._conditionToKql(node.expr, sigmaRule);
                return `not (${inner})`;
            }
            case 'all_of': {
                const parts = node.identifiers.map(id => {
                    const k = Object.keys(sigmaRule.detection.identifiers)
                        .find(k2 => k2.toLowerCase() === id.toLowerCase());
                    const n = sigmaRule.detection.identifiers[k];
                    return this._identifierToKql(n, sigmaRule);
                }).filter(Boolean);
                return parts.reduce((a, b) => `(${a} and ${b})`);
            }
            case 'any_of': {
                const parts = node.identifiers.map(id => {
                    const k = Object.keys(sigmaRule.detection.identifiers)
                        .find(k2 => k2.toLowerCase() === id.toLowerCase());
                    const n = sigmaRule.detection.identifiers[k];
                    return this._identifierToKql(n, sigmaRule);
                }).filter(Boolean);
                return parts.reduce((a, b) => `(${a} or ${b})`);
            }
            default: return `/* unknown node: ${node.type} */`;
        }
    }

    _identifierToKql(node, sigmaRule) {
        if (!node) return '';
        switch (node.type) {
            case 'field_condition':
                return this.buildFieldCondition(node, sigmaRule.logsource);
            case 'and_conditions': {
                const parts = node.conditions.map(c => this._identifierToKql(c, sigmaRule)).filter(Boolean);
                return parts.length === 1 ? parts[0] : `(${parts.join(' and ')})`;
            }
            case 'or_conditions': {
                const parts = node.conditions.map(c => this._identifierToKql(c, sigmaRule)).filter(Boolean);
                return parts.length === 1 ? parts[0] : `(${parts.join(' or ')})`;
            }
            case 'keywords':
                return this.buildKeywords(node.values, sigmaRule.logsource);
            default: return `/* unknown: ${node.type} */`;
        }
    }

    // ── Reverse parser: KQL → Sigma ───────────────────────────────────
    static parseQueryToSigma(kqlQuery) {
        if (!kqlQuery || typeof kqlQuery !== 'string') return '';

        try {
            const comparisons = this._parseKqlComparisons(kqlQuery);
            if (!comparisons.length) {
                return this._buildSigmaKeywords(kqlQuery);
            }

            const detections = this._extractSigmaDetections(comparisons);
            return this._buildSigmaYAML(detections);
        } catch (_err) {
            return this._buildSigmaKeywords(kqlQuery);
        }
    }

    static _buildKqlInverseMap() {
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

                const sec = backendMap.kql_sec;
                const dev = backendMap.kql_dev;

                if (sec && !inverse[sec]) inverse[sec] = sigmaField;
                if (dev && !inverse[dev]) inverse[dev] = sigmaField;
            });
        });

        const byLower = {};
        Object.entries(inverse).forEach(([k, v]) => {
            byLower[k.toLowerCase()] = v;
        });

        return { byExact: inverse, byLower };
    }

    static _mapKqlFieldToSigma(fieldName) {
        if (!this._kqlInverseMapCache) {
            this._kqlInverseMapCache = this._buildKqlInverseMap();
        }

        const raw = String(fieldName || '').trim();
        if (!raw) return raw;

        return this._kqlInverseMapCache.byExact[raw]
            || this._kqlInverseMapCache.byLower[raw.toLowerCase()]
            || raw;
    }

    static _stripQuoted(valueRaw) {
        let v = String(valueRaw || '').trim();
        if (v.startsWith('@')) v = v.slice(1).trim();
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.slice(1, -1);
        }
        return v.replace(/\\'/g, "'").replace(/\\"/g, '"');
    }

    static _parseKqlList(listRaw) {
        const raw = String(listRaw || '').trim().replace(/^\(/, '').replace(/\)$/, '');
        const out = [];
        const rx = /@?'([^'\\]*(?:\\.[^'\\]*)*)'|@?"([^"\\]*(?:\\.[^"\\]*)*)"|([^,\s][^,]*)/g;
        let m;
        while ((m = rx.exec(raw)) !== null) {
            const value = m[1] ?? m[2] ?? (m[3] || '').trim();
            if (value !== '') out.push(value);
        }
        return out;
    }

    static _parseKqlComparisons(kqlQuery) {
        const withoutComments = String(kqlQuery || '')
            .split('\n')
            .map(line => line.replace(/\/\/.*$/, ''))
            .join('\n')
            .trim();

        if (!withoutComments) return [];

        const whereMatch = withoutComments.match(/\|\s*where\b/i);
        let conditionText = whereMatch
            ? withoutComments.slice(whereMatch.index).replace(/\|\s*where\b/gi, ' and ')
            : withoutComments;

        conditionText = conditionText
            .replace(/^\s*and\s+/i, '')
            .split(/\|\s*(?:project|summarize|limit|take|order|extend|parse|join|distinct|count)\b/i)[0]
            .trim();

        const comparisons = [];
        const rx = /\b(not\s+)?([A-Za-z_][\w.]*)\s*(==|=~|!=|!?contains|!?startswith|!?endswith|!?has|matches\s+regex|!matches\s+regex|in~|has_any)\s*(\([^)]*\)|@?'(?:\\.|[^'])*'|@?"(?:\\.|[^"])*"|[^\s)]+)/gi;

        let m;
        while ((m = rx.exec(conditionText)) !== null) {
            const prefixNot = Boolean(m[1]);
            const field = m[2];
            const opRaw = String(m[3]).toLowerCase().replace(/\s+/g, ' ').trim();
            const rhs = String(m[4] || '').trim();

            const sigmaField = this._mapKqlFieldToSigma(field);

            const opNegated = opRaw.startsWith('!') || opRaw === '!=' || opRaw === '!matches regex';
            const negated = prefixNot ? !opNegated : opNegated;

            const op = opRaw
                .replace(/^!/, '')
                .replace(/^!matches regex$/, 'matches regex')
                .replace(/^!=$/, '==');

            if (op === 'in~' || op === 'has_any') {
                const values = this._parseKqlList(rhs);
                values.forEach(v => {
                    comparisons.push({
                        field: sigmaField,
                        value: v,
                        op: op === 'has_any' ? 'contains' : 'equals',
                        negated,
                    });
                });
                continue;
            }

            const normalizedOp = op === 'has' ? 'contains' : op;

            comparisons.push({
                field: sigmaField,
                value: this._stripQuoted(rhs),
                op: normalizedOp,
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
            'title: Imported KQL Query',
            'description: Converted from Microsoft KQL query',
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
            'title: Imported KQL Query',
            'description: Converted from Microsoft KQL query',
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
