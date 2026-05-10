/**
 * carbon-black.js
 * Sigma → Carbon Black EDR / CB Cloud query backend
 *
 * Produces Lucene-style queries for:
 *   - Carbon Black Enterprise EDR (Response) - on-premise
 *   - Carbon Black Cloud (Threat Hunter)
 *
 * References:
 *   https://developer.carbonblack.com/reference/enterprise-response/latest/rest-api/
 *   https://developer.carbonblack.com/reference/carbon-black-cloud/latest/
 *   Carbon Black EEDR skill: uses field:value Lucene syntax
 */
'use strict';

class CarbonBlackBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        // Options: { variant: 'eedr' | 'cloud', addComments: true }
        this.variant     = options.variant || 'eedr';
        this.addComments = options.addComments !== false;
        this.allowLeadingWildcards = options.allowLeadingWildcards === true;
    }

    // ── Logsource header ───────────────────────────────────────────────
    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [];
        if (sigmaRule.title)       lines.push(`# Title: ${sigmaRule.title}`);
        if (sigmaRule.level)       lines.push(`# Level: ${sigmaRule.level}`);
        if (sigmaRule.description) lines.push(`# Description: ${sigmaRule.description.split('\n')[0]}`);
        lines.push(`# Backend: Carbon Black ${this.variant === 'cloud' ? 'Cloud/ThreatHunter' : 'Enterprise EDR'}`);
        return lines.join('\n');
    }

    // ── Field mapping ──────────────────────────────────────────────────
    _mapField(fieldName, logsource) {
        return FieldMaps.mapField(fieldName, logsource, 'cb', true);
    }

    // ── Build a complete field condition ────────────────────────
    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) {
            return null; // unsupported field – caller will skip and warn
        }

        // Null value → NOT field:* (field does not exist / is empty)
        if (node.values.length === 1 && node.values[0] === null) {
            return `-${mappedField}:*`;
        }

        const [primaryMod] = node.modifiers;

        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers));

        if (node.useAll) {
            const combined = parts.reduce((a, b) => `${a} AND ${b}`);
            return parts.length > 1 ? `(${combined})` : combined;
        }

        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        // Regex: Carbon Black doesn't natively support inline regex in process search
        // Use wildcard approximation or note the limitation
        if (primaryMod === 're' || primaryMod === 'regex') {
            // Best-effort: strip anchors/groups, use wildcards
            const approx = this._regexToWildcard(value);
            return approx ? `${field}:${approx}` : `/* regex unsupported: ${field}:/${value}/ */`;
        }

        // CIDR: not natively supported, return raw
        if (primaryMod === 'cidr') {
            return `/* CIDR unsupported in CB – use range: ${field}:[x.x.x.x TO x.x.x.x] */`;
        }

        // Base64
        if (allMods.includes('base64') || allMods.includes('base64offset')) {
            try {
                const decoded = atob(value);
                const escaped = this._escapeCbValue(decoded);
                // EEDR commonly blocks leading wildcards; keep value anchored where possible.
                if (this.variant === 'eedr' && !this.allowLeadingWildcards) return `${field}:${escaped}`;
                return `${field}:*${escaped}*`;
            } catch {
                return `${field}:${this._escapeCbValue(value)}`;
            }
        }

        const escaped = this._escapeCbValue(value);

        switch (primaryMod) {
            case 'contains':
                if (this.variant === 'eedr' && !this.allowLeadingWildcards) return `${field}:${escaped}`;
                return `${field}:*${escaped}*`;
            case 'startswith':  return `${field}:${escaped}*`;
            case 'endswith':
                if (this.variant === 'eedr' && !this.allowLeadingWildcards) return `${field}:${escaped}`;
                return `${field}:*${escaped}`;
            case 'equals':
            case undefined:
            case null:
            case '':
                if (value === null || value === '') return `-${field}:*`;
                if (value.includes('*') || value.includes('?')) {
                    if (this.variant === 'eedr' && !this.allowLeadingWildcards && escaped.startsWith('*')) {
                        return `${field}:${escaped.replace(/^\*+/, '')}`;
                    }
                    return `${field}:${escaped}`;
                }
                return `${field}:${escaped}`;
            default:
                return `${field}:${escaped}`;
        }
    }

    _escapeCbValue(value) {
        if (value === null || value === undefined) return '';
        // Escape Lucene special chars except * and ?
        // CB EEDR also requires escaping backslashes: c:\\: → c\\:
        return String(value)
            .replace(/\\/g, '\\\\')
            .replace(/([+\-!(){}\[\]^"~:\/])/g, '\\$1')
            // Preserve literal spaces for round-trip safety in unquoted terms.
            .replace(/ /g, '\\ ');
    }

    _regexToWildcard(regexStr) {
        // Very rough approximation of a regex as a wildcard
        try {
            let approx = regexStr
                .replace(/^\^/, '')
                .replace(/\$$/, '')
                .replace(/\.\*/g, '*')
                .replace(/\./g, '?')
                .replace(/[+{}()|^$\[\]]/g, '');
            return approx || null;
        } catch {
            return null;
        }
    }

    // ── Keyword search ─────────────────────────────────────────────────
    buildKeywords(values, logsource) {
        const escaped = values.map(v => `"${String(v).replace(/"/g, '\\"')}"`);
        return escaped.length === 1 ? escaped[0] : `(${escaped.join(' OR ')})`;
    }

    // ── Logical operators ──────────────────────────────────────────────
    andExpr(a, b)  { return `${a} AND ${b}`; }
    orExpr(a, b)   { return `(${a} OR ${b})`; }
    notExpr(a)     { return `-${a}`; }
    wrapGroup(a)   { return `(${a})`; }

    convert(sigmaRule) {
        this._skippedFields = [];

        const header = this.buildHeader(sigmaRule);
        const body = this._resolveConditionAstForMerge(sigmaRule.detection.conditionAst, sigmaRule);
        const footer = this.buildFooter(sigmaRule);

        let warning = '';
        if (this._skippedFields.length > 0) {
            const unique = [...new Set(this._skippedFields)];
            const bodyEmpty = !body || !body.trim();
            if (bodyEmpty) {
                warning = this._makeComment(
                    `\u26a0\ufe0f WARNING: All detection filters were removed — ` +
                    `the following fields are not supported for Carbon Black: ${unique.join(', ')}. ` +
                    `No conditions remain in the output.`
                );
            } else {
                warning = this._makeComment(
                    `\u26a0\ufe0f Note: ${unique.length} field(s) not supported for Carbon Black ` +
                    `and were removed: ${unique.join(', ')}`
                );
            }
        }

        return [warning, header, body, footer].filter(p => p && p.trim() !== '').join('\n');
    }

    _resolveConditionAstForMerge(node, sigmaRule) {
        if (!node) return '';
        if (node.type !== 'and') {
            return super._resolveConditionAst(node, sigmaRule);
        }

        const parts = this._collectAndParts(node, sigmaRule)
            .map(part => part && part.trim())
            .filter(Boolean);

        if (parts.length === 0) return '';
        if (parts.length === 1) return parts[0];

        // EEDR process search is stricter; keep explicit per-value negations.
        // Example preferred output: -process_name:\\foo.exe AND -process_name:\\bar.exe
        if (this.variant === 'eedr') {
            return parts.join(' AND ');
        }

        const merged = this._mergeNegatedFieldClauses(parts);
        return merged.length === 1 ? merged[0] : merged.join(' AND ');
    }

    _collectAndParts(node, sigmaRule) {
        if (!node) return [];
        if (node.type === 'and') {
            return [
                ...this._collectAndParts(node.left, sigmaRule),
                ...this._collectAndParts(node.right, sigmaRule),
            ];
        }
        return [super._resolveConditionAst(node, sigmaRule)];
    }

    _mergeNegatedFieldClauses(parts) {
        const result = [];
        const pending = new Map();

        const flushPending = () => {
            const entries = [...pending.values()].sort((a, b) => a.index - b.index);
            entries.forEach(entry => {
                const clause = entry.values.length === 1
                    ? `-${entry.field}:${entry.values[0]}`
                    : `-${entry.field}:(${entry.values.join(' OR ')})`;
                result.splice(entry.index, 0, clause);
                for (const other of entries) {
                    if (other !== entry && other.index >= entry.index) {
                        other.index += 1;
                    }
                }
            });
            pending.clear();
        };

        for (const part of parts) {
            const parsed = this._parseNegatedFieldClause(part);
            if (!parsed) {
                flushPending();
                result.push(part);
                continue;
            }

            const key = parsed.field;
            if (!pending.has(key)) {
                pending.set(key, { field: key, values: [], index: result.length });
            }
            pending.get(key).values.push(...parsed.values);
        }

        flushPending();
        return result;
    }

    _parseNegatedFieldClause(part) {
        if (!part || typeof part !== 'string') return null;

        const raw = part.trim();
        const match = raw.match(/^-([A-Za-z0-9_.]+):(.+)$/);
        if (!match) return null;

        const field = match[1];
        const valueText = match[2].trim();

        if (valueText.startsWith('(') && valueText.endsWith(')')) {
            const inner = valueText.slice(1, -1).trim();
            const values = inner.split(/\s+OR\s+/i).map(v => v.trim()).filter(Boolean);
            if (values.length === 0) return null;
            return { field, values };
        }

        if (valueText.includes(' AND ') || valueText.includes(' OR ') || valueText.startsWith('/*')) {
            return null;
        }

        return { field, values: [valueText] };
    }

    _makeComment(text) { return `/* ${text} */`; }

    // ── Reverse parser: Carbon Black → Sigma ──────────────────────────
    /**
     * Parse a Carbon Black EDR/Cloud query and convert it back to a Sigma rule.
     * @param {string} cbQuery - Carbon Black query string (e.g., "process_name:\\powershell.exe AND ...")
     * @returns {string} YAML Sigma rule with proper selection: blocks
     */
    static parseQueryToSigma(cbQuery) {
        if (!cbQuery || typeof cbQuery !== 'string') return '';

        try {
            // Parse the query into tokens and AST
            const tokens   = QueryParser.tokenize(cbQuery);
            const ast      = QueryParser.buildAST(tokens);
            const comparisons = QueryParser.extractComparisons(ast);

            if (!comparisons.length) {
                // Fallback: keywords block
                return this._buildSigmaKeywords(cbQuery);
            }

            // Build Sigma detection structure
            const detections = this._extractSigmaDetections(ast, comparisons);

            // Return Sigma YAML
            return this._buildSigmaYAML(detections);
        } catch (err) {
            // Fallback on parse error
            return this._buildSigmaKeywords(cbQuery);
        }
    }

    /**
     * Map CB field name to Sigma field name.
     * @private
     */
    static _mapCBFieldToSigma(cbFieldName) {
        const mapping = {
            'process_name': 'Image',
            'cmdline': 'CommandLine',
            'process_cmdline': 'CommandLine',
            'parent_name': 'ParentImage',
            'process_id': 'ProcessId',
            'parent_process_id': 'ParentProcessId',
            'user_name': 'User',
            'md5': 'Hashes.MD5',
            'sha256': 'Hashes.SHA256',
            'registry_path': 'TargetObject',
            'registry_value_name': 'TargetObject',
            'ipv4': 'DestinationIp',
            'port': 'DestinationPort',
            'dns_name': 'QueryName',
        };
        return mapping[cbFieldName?.toLowerCase()] || cbFieldName;
    }

    /**
     * Normalize a parsed Lucene value back to human-readable Sigma text.
     * This prevents repeated backslash growth across multi-hop conversions.
     * @private
     */
    static _normalizeParsedValue(value) {
        if (value === null || value === undefined) return '';

        return String(value)
            // Lucene path escaping: \\foo\\bar -> \foo\bar
            .replace(/\\\\/g, '\\')
            // Escaped spaces in Lucene terms.
            .replace(/\\ /g, ' ')
            // Escaped Lucene special characters should become literal again.
            .replace(/\\([+\-!(){}\[\]^"~:\/])/g, '$1');
    }

    /**
     * Extract detection patterns from parsed comparisons.
     * @private
     */
    static _extractSigmaDetections(ast, comparisons) {
        const detections = {
            selection: {},
            filter_blocks: {},
            conditions: ['selection']
        };

        if (!comparisons.length) return detections;

        const negatedComparisons = new Set();

        // Find all negated comparisons by walking the tree
        QueryParser.walkAST(ast, (node) => {
            if (node.type === 'UnaryOp' && node.op === 'NOT') {
                // Mark all comparisons within this NOT as negated
                this._collectNegatedComparisons(node.operand, negatedComparisons);
            }
        });

        // Process each comparison
        comparisons.forEach(comp => {
            const sigmaField = this._mapCBFieldToSigma(comp.field);
            const isNegated = negatedComparisons.has(comp);
            const operator = comp.operator;
            const normalizedValue = this._normalizeParsedValue(comp.value);

            // Determine Sigma modifier based on operator
            let modifier = '';
            if (operator === '*:*' || operator === 'contains') modifier = '|contains';
            else if (operator === '*:') modifier = '|startswith';
            else if (operator === ':*') modifier = '|endswith';

            // Build the key with modifier
            const fieldKey = modifier ? `${sigmaField}${modifier}` : sigmaField;

            if (!isNegated) {
                if (!detections.selection[fieldKey]) {
                    detections.selection[fieldKey] = [];
                }
                detections.selection[fieldKey].push(normalizedValue);
                return;
            }

            // Build stable filter identifier names that are valid Sigma condition refs.
            // IMPORTANT: Do not include Sigma modifiers (|contains, |endswith, etc.) in the
            // block identifier because condition parser identifiers only allow [a-zA-Z0-9_*].
            const baseName = `filter_${String(sigmaField).replace(/[^A-Za-z0-9_]/g, '_')}`;
            if (!detections.filter_blocks[baseName]) {
                detections.filter_blocks[baseName] = {};
            }
            if (!detections.filter_blocks[baseName][fieldKey]) {
                detections.filter_blocks[baseName][fieldKey] = [];
            }
            detections.filter_blocks[baseName][fieldKey].push(normalizedValue);
        });

        // Build filter conditions if there are negations
        const filterNames = Object.keys(detections.filter_blocks);
        if (filterNames.length > 0) {
            const filterExpr = filterNames.length === 1
                ? filterNames[0]
                : `(${filterNames.join(' or ')})`;
            detections.conditions.push(`not ${filterExpr}`);
        }

        return detections;
    }

    /**
     * Recursively collect all Comparisons within a NOT node.
     * @private
     */
    static _collectNegatedComparisons(node, set) {
        if (!node) return;
        if (node.type === 'Comparison') {
            set.add(node);
        } else if (node.type === 'BinaryOp') {
            this._collectNegatedComparisons(node.left, set);
            this._collectNegatedComparisons(node.right, set);
        } else if (node.type === 'UnaryOp') {
            this._collectNegatedComparisons(node.operand, set);
        }
    }

    /**
     * Build Sigma YAML from detection structure.
     * @private
     */
    static _buildSigmaYAML(detections) {
        const lines = [
            'title: Imported Carbon Black Query',
            'description: Converted from Carbon Black query',
            'logsource:',
            '  product: windows',
            '  category: process_creation',
            'detection:'
        ];

        // Selection block
        if (Object.keys(detections.selection).length) {
            lines.push('  selection:');
            for (const [key, value] of Object.entries(detections.selection)) {
                if (Array.isArray(value)) {
                    if (value.length === 1) {
                        lines.push(`    ${key}: '${value[0].replace(/'/g, "''")}'`);
                    } else {
                        lines.push(`    ${key}:`);
                        value.forEach(v => lines.push(`      - '${v.replace(/'/g, "''")}'`));
                    }
                } else {
                    lines.push(`    ${key}: '${value.replace(/'/g, "''")}'`);
                }
            }
        }

        // Emit named filter blocks as first-class detection identifiers.
        const filterBlocks = detections.filter_blocks || {};
        for (const [filterName, block] of Object.entries(filterBlocks)) {
            lines.push(`  ${filterName}:`);
            for (const [key, value] of Object.entries(block)) {
                if (Array.isArray(value)) {
                    if (value.length === 1) {
                        lines.push(`    ${key}: '${value[0].replace(/'/g, "''")}'`);
                    } else {
                        lines.push(`    ${key}:`);
                        value.forEach(v => lines.push(`      - '${v.replace(/'/g, "''")}'`));
                    }
                } else {
                    lines.push(`    ${key}: '${String(value).replace(/'/g, "''")}'`);
                }
            }
        }

        // Condition
        lines.push(`  condition: ${detections.conditions.join(' and ')}`);
        lines.push('level: medium');

        return lines.join('\n');
    }

    /**
     * Fallback: build keywords-based Sigma YAML.
     * @private
     */
    static _buildSigmaKeywords(cbQuery) {
        const lines = [
            'title: Imported Carbon Black Query',
            'description: Converted from Carbon Black query',
            'logsource:',
            '  product: windows',
            '  category: process_creation',
            'detection:',
            '  selection:',
            `    keywords: '${cbQuery.replace(/'/g, "''")}'`,
            '  condition: selection',
            'level: medium'
        ];
        return lines.join('\n');
    }

}
