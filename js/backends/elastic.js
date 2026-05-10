/**
 * elastic.js
 * Sigma → Elasticsearch Lucene query backend
 *
 * Produces Lucene queries compatible with:
 *   - Elasticsearch / Kibana search
 *   - Elastic SIEM detection rules (Lucene format)
 *
 * References:
 *   https://github.com/SigmaHQ/pySigma-backend-elasticsearch
 *   https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html
 */
'use strict';

class ElasticLuceneBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        // Options: { format: 'lucene' | 'kibana_ndjson', addComments: true }
        this.addComments = options.addComments !== false;
    }

    // ── Logsource header ───────────────────────────────────────────────
    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [];
        if (sigmaRule.title)  lines.push(`// Title: ${sigmaRule.title}`);
        if (sigmaRule.level)  lines.push(`// Level: ${sigmaRule.level}`);
        if (sigmaRule.description) lines.push(`// Description: ${sigmaRule.description.split('\n')[0]}`);
        const ls = sigmaRule.logsource;
        if (ls.product || ls.category || ls.service) {
            lines.push(`// Logsource: ${[ls.product, ls.category || ls.service].filter(Boolean).join('/')}`);
        }
        return lines.join('\n');
    }

    // ── Field mapping ──────────────────────────────────────────────────
    _mapField(fieldName, logsource) {
        return FieldMaps.mapField(fieldName, logsource, 'elastic', true);
    }

    // ── Build a complete field condition ────────────────────────
    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) {
            return null; // unsupported field – caller will skip and warn
        }

        // Handle null value → field does not exist
        if (node.values.length === 1 && node.values[0] === null) {
            return `NOT _exists_:${mappedField}`;
        }

        const [primaryMod] = node.modifiers;

        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers));

        if (node.useAll) {
            const combined = parts.reduce((a, b) => this.andExpr(a, b));
            return parts.length > 1 ? `(${combined})` : combined;
        }

        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        // Regex
        if (primaryMod === 're' || primaryMod === 'regex') {
            return `${field}:/${this._escapeLuceneRegex(value)}/`;
        }

        // CIDR – use Lucene range / IP filter syntax
        if (primaryMod === 'cidr') {
            return `${field}:${value}`;
        }

        // Base64
        if (allMods.includes('base64') || allMods.includes('base64offset')) {
            try {
                const decoded = atob(value);
                const escaped = this._escapeLuceneValue(decoded);
                return `${field}:*${escaped}*`;
            } catch {
                return `${field}:${this._escapeLuceneValue(value)}`;
            }
        }

        const escaped = this._escapeLuceneValue(value);

        switch (primaryMod) {
            case 'contains':    return `${field}:*${escaped}*`;
            case 'startswith':  return `${field}:${escaped}*`;
            case 'endswith':    return `${field}:*${escaped}`;
            case 'equals':
            case undefined:
            case null:
            case '':
                if (value === null || value === '') return `NOT _exists_:${field}`;
                if (value.includes('*') || value.includes('?')) {
                    return `${field}:${escaped}`;
                }
                return `${field}:"${this._escapeLucenePhraseValue(value)}"`;
            default:
                return `${field}:${escaped}`;
        }
    }

    // Escape special Lucene characters in a wildcard context (no quotes)
    _escapeLuceneValue(value) {
        if (value === null || value === undefined) return '';
        // Escape special Lucene chars EXCEPT * and ? (wildcards)
        return String(value)
            .replace(/([+\-!(){}\[\]^"~:\\/ ])/g, '\\$1');
    }

    // Escape for quoted phrase (escape internal quotes and backslashes)
    _escapeLucenePhraseValue(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/\\/g, '\\\\')
            .replace(/"/g, '\\"');
    }

    _escapeLuceneRegex(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/\//g, '\\/');
    }

    // ── Keyword search ─────────────────────────────────────────────────
    buildKeywords(values, logsource) {
        const escaped = values.map(v => `"${this._escapeLucenePhraseValue(v)}"`);
        return escaped.length === 1 ? escaped[0] : `(${escaped.join(' OR ')})`;
    }

    // ── Logical operators ──────────────────────────────────────────────
    andExpr(a, b)  { return `(${a} AND ${b})`; }
    orExpr(a, b)   { return `(${a} OR ${b})`; }
    notExpr(a)     { return `NOT ${a}`; }
    wrapGroup(a)   { return `(${a})`; }

    // ── Reverse: Elastic Lucene → Sigma YAML ─────────────────────────
    /**
     * Parse an Elasticsearch Lucene query string and return a Sigma YAML rule.
     * Reuses QueryParser (same Lucene-style AST used by the CB reverse parser).
     */
    static parseQueryToSigma(elasticQuery) {
        if (!elasticQuery || typeof elasticQuery !== 'string') return '';

        try {
            const tokens = QueryParser.tokenize(elasticQuery);
            const ast    = QueryParser.buildAST(tokens);
            const comparisons = QueryParser.extractComparisons(ast);

            if (!comparisons.length) {
                return ElasticLuceneBackend._buildSigmaKeywords(elasticQuery);
            }

            const detections = ElasticLuceneBackend._extractSigmaDetections(ast, comparisons);
            return ElasticLuceneBackend._buildSigmaYAML(detections);
        } catch (_err) {
            return ElasticLuceneBackend._buildSigmaKeywords(elasticQuery);
        }
    }

    /** Map an ECS field name to its Sigma equivalent. */
    static _mapElasticFieldToSigma(field) {
        const mapping = {
            // Process creation / execution
            'process.executable':           'Image',
            'process.command_line':         'CommandLine',
            'process.parent.executable':    'ParentImage',
            'process.parent.command_line':  'ParentCommandLine',
            'process.pid':                  'ProcessId',
            'process.parent.pid':           'ParentProcessId',
            'process.working_directory':    'CurrentDirectory',
            'process.pe.original_file_name': 'OriginalFileName',
            'process.pe.product':           'Product',
            'process.pe.description':       'Description',
            'process.pe.company':           'Company',
            'process.hash.md5':             'md5',
            'process.hash.sha256':          'sha256',
            // User / host
            'user.name':                    'User',
            'host.name':                    'ComputerName',
            // Network
            'destination.ip':               'DestinationIp',
            'destination.port':             'DestinationPort',
            'destination.domain':           'DestinationHostname',
            'source.ip':                    'SourceIp',
            'source.port':                  'SourcePort',
            'network.transport':            'Protocol',
            // File
            'file.path':                    'TargetFilename',
            'file.name':                    'TargetFilename',
            // Registry
            'registry.path':                'TargetObject',
            'registry.data.strings':        'Details',
            // DLL / image load
            'dll.path':                     'ImageLoaded',
            // DNS
            'dns.question.name':            'QueryName',
            'dns.question.type':            'QueryType',
            // Generic
            'event.code':                   'EventID',
            'winlog.event_data.LogonType':  'LogonType',
            'winlog.event_data.LogonId':    'LogonId',
        };
        return mapping[field] || field;
    }

    static _extractSigmaDetections(ast, comparisons) {
        const detections = {
            selection: {},
            filter_blocks: {},
            conditions: ['selection'],
        };

        const negatedComparisons = new Set();
        QueryParser.walkAST(ast, (node) => {
            if (node.type === 'UnaryOp' && node.op === 'NOT') {
                ElasticLuceneBackend._collectNegated(node.operand, negatedComparisons);
            }
        });

        comparisons.forEach(comp => {
            const sigmaField = ElasticLuceneBackend._mapElasticFieldToSigma(comp.field);
            const isNegated  = negatedComparisons.has(comp);
            const op         = comp.operator;

            let modifier = '';
            if (op === '*:*' || op === 'contains') modifier = '|contains';
            else if (op === '*:')                   modifier = '|startswith';
            else if (op === ':*')                   modifier = '|endswith';

            const fieldKey = modifier ? `${sigmaField}${modifier}` : sigmaField;

            if (!isNegated) {
                detections.selection[fieldKey] = detections.selection[fieldKey] || [];
                detections.selection[fieldKey].push(comp.value);
                return;
            }

            const baseName = `filter_${String(sigmaField).replace(/[^A-Za-z0-9_]/g, '_')}`;
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

    static _collectNegated(node, set) {
        if (!node) return;
        if (node.type === 'Comparison') { set.add(node); return; }
        if (node.type === 'BinaryOp') {
            ElasticLuceneBackend._collectNegated(node.left, set);
            ElasticLuceneBackend._collectNegated(node.right, set);
        } else if (node.type === 'UnaryOp') {
            ElasticLuceneBackend._collectNegated(node.operand, set);
        }
    }

    static _buildSigmaYAML(detections) {
        const lines = [
            'title: Imported Elastic Lucene Query',
            'description: Converted from Elasticsearch Lucene query',
            'logsource:',
            '  product: windows',
            '  category: process_creation',
            'detection:',
        ];

        if (Object.keys(detections.selection).length) {
            lines.push('  selection:');
            for (const [key, values] of Object.entries(detections.selection)) {
                if (values.length === 1) {
                    lines.push(`    ${key}: '${values[0].replace(/'/g, "''")}'`);
                } else {
                    lines.push(`    ${key}:`);
                    values.forEach(v => lines.push(`      - '${v.replace(/'/g, "''")}'`));
                }
            }
        }

        for (const [filterName, block] of Object.entries(detections.filter_blocks)) {
            lines.push(`  ${filterName}:`);
            for (const [key, values] of Object.entries(block)) {
                if (values.length === 1) {
                    lines.push(`    ${key}: '${values[0].replace(/'/g, "''")}'`);
                } else {
                    lines.push(`    ${key}:`);
                    values.forEach(v => lines.push(`      - '${v.replace(/'/g, "''")}'`));
                }
            }
        }

        lines.push(`  condition: ${detections.conditions.join(' and ')}`);

        return lines.join('\n');
    }

    static _buildSigmaKeywords(raw) {
        const trimmed = String(raw || '').trim().replace(/'/g, "''");
        return [
            'title: Imported Elastic Lucene Query',
            'description: Converted from Elasticsearch Lucene query',
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

