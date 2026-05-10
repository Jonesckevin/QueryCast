/**
 * siem-generic.js
 * Real backends for additional SIEM query formats used by QueryCast.
 */
'use strict';

const COMMON_FIELD_MAP = {
    EventID: 'event_id',
    Image: 'process_name',
    CommandLine: 'command_line',
    ParentImage: 'parent_process_name',
    ParentCommandLine: 'parent_command_line',
    ProcessId: 'process_id',
    ParentProcessId: 'parent_process_id',
    User: 'user',
    ComputerName: 'host',
    TargetFilename: 'file_path',
    QueryName: 'dns_query',
    QueryResults: 'dns_answers',
    DestinationIp: 'dest_ip',
    DestinationPort: 'dest_port',
    SourceIp: 'src_ip',
    SourcePort: 'src_port',
    Hashes: 'hash',
    md5: 'md5',
    sha256: 'sha256',
};

class GenericQueryBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        this.addComments = options.addComments !== false;
        this.backendLabel = options.backendLabel || 'SIEM Query';
        this.commentPrefix = options.commentPrefix || '--';
        this.queryPrefix = options.queryPrefix || '';
        this.querySuffix = options.querySuffix || '';
        this.fieldMap = options.fieldMap || COMMON_FIELD_MAP;
    }

    convert(sigmaRule) {
        // Reset per-conversion tracking
        this._skippedFields = [];

        const header = this.buildHeader(sigmaRule);
        const query  = this._buildQuery(sigmaRule);
        const footer = this.buildFooter(sigmaRule);

        let warning = '';
        if (this._skippedFields.length > 0) {
            const unique = [...new Set(this._skippedFields)];
            const empty = !query || !query.trim();
            if (empty) {
                warning = `${this.commentPrefix} ⚠️ WARNING: All detection filters removed — ` +
                    `the following fields are not supported: ${unique.join(', ')}. No conditions remain.`;
            } else {
                warning = `${this.commentPrefix} ⚠️ Note: ${unique.length} field(s) not supported and removed: ${unique.join(', ')}`;
            }
        }

        return [warning, header, query, footer].filter(p => p && p.trim() !== '').join('\n');
    }

    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [];
        if (sigmaRule.title) lines.push(`${this.commentPrefix} Title: ${sigmaRule.title}`);
        if (sigmaRule.level) lines.push(`${this.commentPrefix} Level: ${sigmaRule.level}`);
        if (sigmaRule.description) lines.push(`${this.commentPrefix} Description: ${sigmaRule.description.split('\n')[0]}`);
        lines.push(`${this.commentPrefix} Backend: ${this.backendLabel}`);
        return lines.join('\n');
    }

    _buildQuery(sigmaRule) {
        const condition = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        if (!condition || !condition.trim()) return '';
        return [this.queryPrefix, condition, this.querySuffix].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
    }

    // Strict-mode field mapping:
    //  1. If in the explicit override fieldMap → use mapped name
    //  2. If it IS a known Sigma field (present in any FieldMaps table) → passthrough (best-effort)
    //  3. Completely unknown (cloud fields, typos, etc.) → null (will be dropped with a warning)
    _mapField(fieldName, logsource) {
        if (Object.prototype.hasOwnProperty.call(this.fieldMap, fieldName)) {
            return this.fieldMap[fieldName];
        }
        if (FieldMaps.isKnownField(fieldName)) {
            return fieldName; // known Sysmon/Win field – pass raw name (best-effort)
        }
        return null; // completely unknown – drop
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // base-backend._resolveIdentifier tracks _skippedFields

        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField} IS NULL`;
        }

        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers));

        if (node.useAll) {
            return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        }

        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        if (primaryMod === 're' || primaryMod === 'regex') {
            return `${field} REGEXP '${this._escapeSqlishString(value)}'`;
        }

        if (primaryMod === 'cidr') {
            return `${field} = '${this._escapeSqlishString(value)}'`;
        }

        if (allMods.includes('base64') || allMods.includes('base64offset')) {
            try {
                const decoded = atob(value);
                return `${field} LIKE '%${this._escapeSqlishString(decoded)}%'`;
            } catch {
                return `${field} LIKE '%${this._escapeSqlishString(value)}%'`;
            }
        }

        const escaped = this._escapeSqlishString(value);
        switch (primaryMod) {
            case 'contains':
                return `${field} LIKE '%${escaped}%'`;
            case 'startswith':
                return `${field} LIKE '${escaped}%'`;
            case 'endswith':
                return `${field} LIKE '%${escaped}'`;
            case 'equals':
            case undefined:
            case null:
            case '':
                if (value === null || value === '') return `${field} IS NULL`;
                if (value.includes('*') || value.includes('?')) {
                    return `${field} LIKE '${this._globToLike(value)}'`;
                }
                return `${field} = '${escaped}'`;
            default:
                return `${field} = '${escaped}'`;
        }
    }

    _escapeSqlishString(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/'/g, "''").replace(/\\/g, '\\\\');
    }

    _globToLike(glob) {
        return String(glob)
            .replace(/([%_])/g, '\\$1')
            .replace(/\*/g, '%')
            .replace(/\?/g, '_');
    }

    buildKeywords(values, logsource) {
        if (values.length === 1) {
            return `'${this._escapeSqlishString(values[0])}'`;
        }
        return `(${values.map(v => `'${this._escapeSqlishString(v)}'`).join(' OR ')})`;
    }

    andExpr(a, b)  { return `(${a} AND ${b})`; }
    orExpr(a, b)   { return `(${a} OR ${b})`; }
    notExpr(a)     { return `NOT (${a})`; }
    wrapGroup(a)   { return `(${a})`; }
}

class AqlBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'IBM QRadar AQL',
            commentPrefix: '--',
            queryPrefix: 'SELECT * FROM events WHERE',
            querySuffix: 'LAST 24 HOURS',
        });
    }
}

class NetWitnessBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'RSA NetWitness Query',
            commentPrefix: '--',
            queryPrefix: 'SELECT * FROM events WHERE',
            // Fallback aliases; strict mode still prefers FieldMaps when available.
            fieldMap: {
                ...COMMON_FIELD_MAP,
                Image: 'process',
                CommandLine: 'command',
                ParentImage: 'parent.process',
                User: 'user',
                ComputerName: 'host',
                SourceIp: 'ip.src',
                SourcePort: 'port.src',
                DestinationIp: 'ip.dst',
                DestinationPort: 'port.dst',
                QueryName: 'dns.query',
                TargetFilename: 'filename',
                TargetObject: 'registry.key',
                EventID: 'event.id',
            },
        });
    }
}

class PplBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'OpenSearch PPL',
            commentPrefix: '--',
            queryPrefix: 'source = logs | where',
        });
    }
}

class XqlBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        this.addComments = options.addComments !== false;
    }

    convert(sigmaRule) {
        this._skippedFields = [];
        const header = this.buildHeader(sigmaRule);
        const body   = this._buildQuery(sigmaRule);
        let warning = '';
        if (this._skippedFields.length > 0) {
            const unique = [...new Set(this._skippedFields)];
            const empty = !body || !body.trim();
            warning = empty
                ? `-- ⚠️ WARNING: All filters removed — fields not supported for Cortex XDR XQL: ${unique.join(', ')}`
                : `-- ⚠️ Note: ${unique.length} field(s) not supported removed: ${unique.join(', ')}`;
        }
        return [warning, header, body].filter(p => p && p.trim()).join('\n');
    }

    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [`-- Backend: Palo Alto Cortex XDR XQL`];
        if (sigmaRule.title) lines.unshift(`-- Title: ${sigmaRule.title}`);
        if (sigmaRule.level) lines.splice(1, 0, `-- Level: ${sigmaRule.level}`);
        return lines.join('\n');
    }

    _buildQuery(sigmaRule) {
        const eventFilter = this._getEventTypeFilter(sigmaRule.logsource);
        const cond = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        const filterParts = [eventFilter, cond].filter(Boolean);
        const filterClause = filterParts.length > 0 ? `| filter ${filterParts.join(' and ')}` : '';
        return `dataset = xdr_data\n${filterClause}`.trim();
    }

    _getEventTypeFilter(logsource) {
        const key = FieldMaps.getLogsourceKey(logsource);
        switch (key) {
            case 'windows/process_creation':  return 'event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START';
            case 'windows/network_connection': return 'event_type = ENUM.NETWORK';
            case 'windows/file_event':
            case 'windows/file_creation':     return 'event_type = ENUM.FILE';
            case 'windows/registry_event':
            case 'windows/registry_set':
            case 'windows/registry_add':      return 'event_type = ENUM.REGISTRY';
            case 'windows/dns_query':          return 'event_type = ENUM.NETWORK and action_dns_query_name != null';
            case 'windows/image_load':         return 'event_type = ENUM.LOAD_IMAGE';
            default:                           return '';
        }
    }

    _mapField(fieldName, logsource) {
        return FieldMaps.mapField(fieldName, logsource, 'xql', true);
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // base-backend tracks _skippedFields
        if (node.values.length === 1 && node.values[0] === null) return `${mappedField} = null`;

        const [primaryMod] = node.modifiers;

        if (node.useAll) {
            return node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers)).join(' and ');
        }

        if (node.values.length === 1) return this._buildSingleValue(mappedField, node.values[0], primaryMod, node.modifiers);

        // Multi-value shortcuts for XQL
        if (!primaryMod || primaryMod === 'equals') {
            return `${mappedField} in (${node.values.map(v => `"${this._esc(v)}"`).join(', ')})`;
        }
        if (primaryMod === 'contains') {
            return `${mappedField} in wildcard (${node.values.map(v => `"*${this._esc(v)}*"`).join(', ')})`;
        }
        if (primaryMod === 'startswith') {
            return `${mappedField} in wildcard (${node.values.map(v => `"${this._esc(v)}*"`).join(', ')})`;
        }
        if (primaryMod === 'endswith') {
            return `${mappedField} in wildcard (${node.values.map(v => `"*${this._esc(v)}"`).join(', ')})`;
        }
        return `(${node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers)).join(' or ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        if (primaryMod === 're' || primaryMod === 'regex') return `${field} ~= "${this._esc(value)}"`;
        if (primaryMod === 'cidr') return `${field} = "${value}"`;
        const e = this._esc(value);
        switch (primaryMod) {
            case 'contains':   return `${field} contains "${e}"`;
            case 'startswith': return `${field} starts_with "${e}"`;
            case 'endswith':   return `${field} ends_with "${e}"`;
            default:
                if (value === null || value === '') return `${field} = null`;
                return `${field} = "${e}"`;
        }
    }

    _esc(v) {
        if (v === null || v === undefined) return '';
        return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        if (values.length === 1) return `to_string(all_fields) contains "${this._esc(values[0])}"`;
        return `(${values.map(v => `to_string(all_fields) contains "${this._esc(v)}"`).join(' or ')})`;
    }

    andExpr(a, b) { return `${a} and ${b}`; }
    orExpr(a, b)  { return `(${a} or ${b})`; }
    notExpr(a)    { return `not (${a})`; }
    wrapGroup(a)  { return `(${a})`; }
    _makeComment(text) { return `-- ${text}`; }
}

class OqlBackend extends GenericQueryBackend {
    constructor(options = {}) {
        const flavor = options.flavor || 'securonix';
        super({
            ...options,
            backendLabel: flavor === 'securityonion' ? 'Security Onion OQL' : 'Securonix OQL',
            commentPrefix: '--',
            queryPrefix: flavor === 'securityonion' ? 'FROM alerts WHERE' : 'FROM security_events WHERE',
        });
        this.flavor = flavor;
    }
}

class ArcSightBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'ArcSight Query',
            commentPrefix: '--',
            queryPrefix: 'SELECT * FROM events WHERE',
        });
    }
}

class DdqlBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Datadog Log Query',
            commentPrefix: '--',
            queryPrefix: 'logs(',
            querySuffix: ')',
        });
    }
}

class S1qlBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        this.addComments = options.addComments !== false;
    }

    convert(sigmaRule) {
        this._skippedFields = [];
        const header = this.buildHeader(sigmaRule);
        const body   = this._buildQuery(sigmaRule);
        let warning = '';
        if (this._skippedFields.length > 0) {
            const unique = [...new Set(this._skippedFields)];
            const empty = !body || !body.trim();
            warning = empty
                ? `// ⚠️ WARNING: All filters removed — fields not supported for SentinelOne DV: ${unique.join(', ')}`
                : `// ⚠️ Note: ${unique.length} field(s) not supported removed: ${unique.join(', ')}`;
        }
        return [warning, header, body].filter(p => p && p.trim()).join('\n');
    }

    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [`// Backend: SentinelOne Deep Visibility`];
        if (sigmaRule.title) lines.unshift(`// Title: ${sigmaRule.title}`);
        if (sigmaRule.level) lines.splice(1, 0, `// Level: ${sigmaRule.level}`);
        return lines.join('\n');
    }

    _buildQuery(sigmaRule) {
        const eventFilter = this._getEventTypeFilter(sigmaRule.logsource);
        const cond = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        return [eventFilter, cond].filter(Boolean).join(' AND ');
    }

    _getEventTypeFilter(logsource) {
        const key = FieldMaps.getLogsourceKey(logsource);
        switch (key) {
            case 'windows/process_creation':  return 'EventType = "Process Creation"';
            case 'windows/network_connection': return 'EventType In ("IP Connect", "IP Listen")';
            case 'windows/file_event':
            case 'windows/file_creation':     return 'EventType In ("File Creation", "File Modification", "File Deletion")';
            case 'windows/registry_event':
            case 'windows/registry_set':
            case 'windows/registry_add':      return 'EventType In ("Registry Value Modified", "Registry Key Created", "Registry Key Deleted")';
            case 'windows/dns_query':          return 'EventType = "DNS Resolved"';
            case 'windows/image_load':         return 'EventType = "Module Load"';
            default:                           return '';
        }
    }

    _mapField(fieldName, logsource) {
        return FieldMaps.mapField(fieldName, logsource, 's1', true);
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // base-backend tracks _skippedFields
        if (node.values.length === 1 && node.values[0] === null) return `NOT ${mappedField} Exists`;

        const [primaryMod] = node.modifiers;

        if (node.useAll) {
            return node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers)).join(' AND ');
        }

        if (node.values.length === 1) return this._buildSingleValue(mappedField, node.values[0], primaryMod, node.modifiers);

        // Multi-value shortcuts
        if (!primaryMod || primaryMod === 'equals') {
            return `${mappedField} In (${node.values.map(v => `"${this._esc(v)}"`).join(', ')})`;
        }
        if (primaryMod === 'contains') {
            return `${mappedField} In Contains Anycase (${node.values.map(v => `"${this._esc(v)}"`).join(', ')})`;
        }
        return `(${node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers)).join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        if (primaryMod === 're' || primaryMod === 'regex') return `${field} REGEXPCIS "${this._esc(value)}"`;
        const e = this._esc(value);
        switch (primaryMod) {
            case 'contains':   return `${field} ContainsCIS "${e}"`;
            case 'startswith': return `${field} StartsWithCIS "${e}"`;
            case 'endswith':   return `${field} EndsWithCIS "${e}"`;
            default:
                if (value === null || value === '') return `NOT ${field} Exists`;
                return `${field} = "${e}"`;
        }
    }

    _esc(v) {
        if (v === null || v === undefined) return '';
        return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        if (values.length === 1) return `EventData ContainsCIS "${this._esc(values[0])}"`;
        return `(${values.map(v => `EventData ContainsCIS "${this._esc(v)}"`).join(' OR ')})`;
    }

    andExpr(a, b) { return `${a} AND ${b}`; }
    orExpr(a, b)  { return `(${a} OR ${b})`; }
    notExpr(a)    { return `NOT (${a})`; }
    wrapGroup(a)  { return `(${a})`; }
    _makeComment(text) { return `// ${text}`; }
}

class EqlBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        this.addComments = options.addComments !== false;
    }

    convert(sigmaRule) {
        this._skippedFields = [];
        const header = this.buildHeader(sigmaRule);
        const body   = this._buildEqlQuery(sigmaRule);
        const footer = this.buildFooter(sigmaRule);

        let warning = '';
        if (this._skippedFields.length > 0) {
            const unique = [...new Set(this._skippedFields)];
            warning = `/* ⚠️ Note: ${unique.length} field(s) not supported for EQL and removed: ${unique.join(', ')} */`;
        }
        return [warning, header, body, footer].filter(p => p && p.trim()).join('\n');
    }

    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [];
        if (sigmaRule.title)       lines.push(`// Title: ${sigmaRule.title}`);
        if (sigmaRule.level)       lines.push(`// Level: ${sigmaRule.level}`);
        if (sigmaRule.description) lines.push(`// Description: ${sigmaRule.description.split('\n')[0]}`);
        return lines.join('\n');
    }

    _buildEqlQuery(sigmaRule) {
        const eventCat = this._getEventCategory(sigmaRule.logsource);
        const cond = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        if (!cond || !cond.trim()) return `${eventCat} where true /* all filters removed – see warning above */`;
        return `${eventCat} where ${cond}`;
    }

    // EQL event category based on Sigma logsource
    _getEventCategory(logsource) {
        const key = FieldMaps.getLogsourceKey(logsource);
        switch (key) {
            case 'windows/process_creation': return 'process';
            case 'windows/network_connection': return 'network';
            case 'windows/file_event':
            case 'windows/file_creation':    return 'file';
            case 'windows/registry_event':
            case 'windows/registry_set':
            case 'windows/registry_add':     return 'registry';
            case 'windows/dns_query':        return 'network';
            case 'windows/image_load':       return 'library';
            default:                         return 'any';
        }
    }

    _mapField(fieldName, logsource) {
        // EQL uses ECS field names (same as Elastic Lucene backend)
        return FieldMaps.mapField(fieldName, logsource, 'elastic', true);
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // base-backend tracks _skippedFields
        if (node.values.length === 1 && node.values[0] === null) return `${mappedField} == null`;

        const [primaryMod] = node.modifiers;

        if (node.useAll) {
            return node.values
                .map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers))
                .join(' and ');
        }

        if (node.values.length === 1) return this._buildSingleValue(mappedField, node.values[0], primaryMod, node.modifiers);
        return this._buildMultiValue(mappedField, node.values, primaryMod);
    }

    // EQL supports native multi-value forms: in~(), like~()
    _buildMultiValue(field, values, primaryMod) {
        const esc = v => this._esc(v);
        if (!primaryMod || primaryMod === 'equals') {
            return `${field} in~ (${values.map(v => `"${esc(v)}"`).join(', ')})`;
        }
        if (primaryMod === 'contains' || primaryMod === 'startswith' || primaryMod === 'endswith') {
            const pats = values.map(v => {
                const e = esc(v);
                if (primaryMod === 'contains')   return `"*${e}*"`;
                if (primaryMod === 'startswith') return `"${e}*"`;
                return `"*${e}"`;
            });
            return `${field} like~ (${pats.join(', ')})`;
        }
        return `(${values.map(v => this._buildSingleValue(field, v, primaryMod, [])).join(' or ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        if (primaryMod === 're' || primaryMod === 'regex') return `${field} regex~ "${this._escRe(value)}"`;
        if (primaryMod === 'cidr') return `${field} like "${this._esc(value)}"`; // no native CIDR
        if (allMods && (allMods.includes('base64') || allMods.includes('base64offset'))) {
            try { return `${field} like~ "*${this._esc(atob(value))}*"`; } catch { /**/ }
        }
        const e = this._esc(value);
        switch (primaryMod) {
            case 'contains':   return `${field} like~ "*${e}*"`;
            case 'startswith': return `${field} like~ "${e}*"`;
            case 'endswith':   return `${field} like~ "*${e}"`;
            default:
                if (value === null || value === '') return `${field} == null`;
                // Use like~ for case-insensitive equality (Sigma is case-insensitive by default)
                if (value.includes('*') || value.includes('?')) return `${field} like~ "${e}"`;
                return `${field} like~ "${e}"`;
        }
    }

    _esc(v) {
        if (v === null || v === undefined) return '';
        return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }
    _escRe(v) { return String(v || '').replace(/"/g, '\\"'); }

    buildKeywords(values, logsource) {
        if (values.length === 1) return `"${this._esc(values[0])}"`;
        return `(${values.map(v => `"${this._esc(v)}"`).join(' or ')})`;
    }

    andExpr(a, b) { return `${a} and ${b}`; }
    orExpr(a, b)  { return `(${a} or ${b})`; }
    notExpr(a)    { return `not (${a})`; }
    wrapGroup(a)  { return `(${a})`; }
    _makeComment(text) { return `/* ${text} */`; }
}

class GraylogBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Graylog Query String',
            commentPrefix: '//',
        });
    }

    _buildQuery(sigmaRule) {
        return this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
    }

    // Graylog with Beats/ECS ingest uses the same ECS field names as Elastic Lucene
    _mapField(fieldName, logsource) {
        const ecs = FieldMaps.mapField(fieldName, logsource, 'elastic', true);
        if (ecs !== null) return ecs;
        // Fall back to generic strict logic
        return super._mapField(fieldName, logsource);
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // base-backend tracks _skippedFields
        if (node.values.length === 1 && node.values[0] === null) {
            return `NOT _exists_:${mappedField}`;
        }

        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers));

        if (node.useAll) {
            return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        }
        return parts.length > 1 ? `(${parts.join(' OR ')})` : parts[0];
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        const escaped = this._escapeGraylog(value);
        switch (primaryMod) {
            case 'contains':
                return `${field}:*${escaped}*`;
            case 'startswith':
                return `${field}:${escaped}*`;
            case 'endswith':
                return `${field}:*${escaped}`;
            case 're':
            case 'regex':
                return `${field}:/${this._escapeRegex(value)}/`;
            default:
                if (value === null || value === '') return `NOT _exists_:${field}`;
                if (value.includes('*') || value.includes('?')) return `${field}:${escaped}`;
                return `${field}:"${escaped}"`;
        }
    }

    _escapeGraylog(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    _escapeRegex(value) {
        return String(value || '').replace(/\//g, '\\/');
    }
}

class SumoBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Sumo Logic',
            commentPrefix: '//',
            queryPrefix: '_sourceCategory=*',
            querySuffix: '| where',
        });
    }

    _buildQuery(sigmaRule) {
        const condition = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        return `_sourceCategory=* | where ${condition}`;
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (node.values.length === 1 && node.values[0] === null) {
            return `isNull(${mappedField})`;
        }

        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod, node.modifiers));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' and ')})` : parts[0];
        return parts.length > 1 ? `(${parts.join(' or ')})` : parts[0];
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        const escaped = this._escapeSqlishString(value);
        switch (primaryMod) {
            case 'contains':
                return `${field} matches "*${escaped}*"`;
            case 'startswith':
                return `${field} matches "${escaped}*"`;
            case 'endswith':
                return `${field} matches "*${escaped}"`;
            case 're':
            case 'regex':
                return `${field} matches /${this._escapeRegex(value)}/`;
            default:
                if (value === null || value === '') return `isNull(${field})`;
                if (value.includes('*') || value.includes('?')) {
                    return `${field} matches "${String(value).replace(/"/g, '\\"')}"`;
                }
                return `${field} = "${escaped}"`;
        }
    }

    _escapeRegex(value) {
        return String(value || '').replace(/\//g, '\\/');
    }
}

class LogScaleBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Falcon LogScale',
            commentPrefix: '#',
        });
    }

    _buildQuery(sigmaRule) {
        return this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (node.values.length === 1 && node.values[0] === null) {
            return `isNull(${mappedField})`;
        }

        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' and ')})` : parts[0];
        return parts.length > 1 ? `(${parts.join(' or ')})` : parts[0];
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeSqlishString(value);
        switch (primaryMod) {
            case 'contains':
                return `${field}=*${escaped}*`;
            case 'startswith':
                return `${field}=${escaped}*`;
            case 'endswith':
                return `${field}=*${escaped}`;
            case 're':
            case 'regex':
                return `${field}=/${String(value || '').replace(/\//g, '\\/')}/`;
            default:
                if (value === null || value === '') return `isNull(${field})`;
                if (value.includes('*') || value.includes('?')) return `${field}=${value}`;
                return `${field}="${escaped}"`;
        }
    }
}

class LogqlBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Grafana Loki LogQL',
            commentPrefix: '#',
            queryPrefix: '{job=~".+"} | json |',
        });
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField} = ""`;
        }

        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' and ')})` : parts[0];
        return parts.length > 1 ? `(${parts.join(' or ')})` : parts[0];
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeSqlishString(value);
        switch (primaryMod) {
            case 'contains':
                return `${field} =~ "(?i).*${escaped}.*"`;
            case 'startswith':
                return `${field} =~ "(?i)${escaped}.*"`;
            case 'endswith':
                return `${field} =~ "(?i).*${escaped}$"`;
            case 're':
            case 'regex':
                return `${field} =~ "${String(value || '').replace(/"/g, '\\"')}"`;
            default:
                if (value === null || value === '') return `${field} = ""`;
                return `${field} = "${escaped}"`;
        }
    }
}

class CloudWatchBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'CloudWatch Logs Insights',
            commentPrefix: '#',
        });
    }

    convert(sigmaRule) {
        const header = this.buildHeader(sigmaRule);
        const cond = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        const query = [
            'fields @timestamp, @message, @logStream',
            `| filter ${cond}`,
            '| sort @timestamp desc',
            '| limit 200',
        ].join('\n');
        return [header, query].filter(Boolean).join('\n');
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (node.values.length === 1 && node.values[0] === null) {
            return `ispresent(${mappedField}) = false`;
        }

        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' and ')})` : parts[0];
        return parts.length > 1 ? `(${parts.join(' or ')})` : parts[0];
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeSqlishString(value);
        switch (primaryMod) {
            case 'contains':
                return `${field} like /${escaped}/`;
            case 'startswith':
                return `${field} like /^${escaped}/`;
            case 'endswith':
                return `${field} like /${escaped}$/`;
            case 're':
            case 'regex':
                return `${field} like /${String(value || '').replace(/\//g, '\\/')}/`;
            default:
                if (value === null || value === '') return `ispresent(${field}) = false`;
                return `${field} = "${escaped}"`;
        }
    }
}

class ChronicleUdmBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Google Chronicle UDM Search',
            commentPrefix: '#',
            // fieldMap acts as fallback only when FieldMaps returns null
            fieldMap: {
                ...COMMON_FIELD_MAP,
                Image:             'principal.process.file.full_path',
                CommandLine:       'principal.process.command_line',
                ParentImage:       'principal.process.parent_process.file.full_path',
                User:              'principal.user.userid',
                ComputerName:      'principal.hostname',
                DestinationIp:     'target.ip',
                DestinationPort:   'target.port',
                DestinationHostname: 'target.hostname',
                SourceIp:          'principal.ip',
                SourcePort:        'principal.port',
                QueryName:         'network.dns.questions.name',
                QueryResults:      'network.dns.answers.data',
                TargetFilename:    'target.file.full_path',
                ImageLoaded:       'target.file.full_path',
                SubjectUserName:   'principal.user.userid',
                TargetUserName:    'target.user.userid',
                IpAddress:         'principal.ip',
            },
        });
    }

    _buildQuery(sigmaRule) {
        return this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
    }

    // Prefer UDM-specific field names from FieldMaps, fall back to override fieldMap
    _mapField(fieldName, logsource) {
        const udm = FieldMaps.mapField(fieldName, logsource, 'udm', true);
        if (udm !== null) return udm;
        // Fall back to the static override map (covers fields not in FieldMaps tables)
        return super._mapField(fieldName, logsource);
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField} = ""`;
        }

        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        return parts.length > 1 ? `(${parts.join(' OR ')})` : parts[0];
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeSqlishString(value);
        switch (primaryMod) {
            case 'contains':
                return `${field} = /${escaped}/ nocase`;
            case 'startswith':
                return `${field} = /^${escaped}/ nocase`;
            case 'endswith':
                return `${field} = /${escaped}$/ nocase`;
            case 're':
            case 'regex':
                return `${field} = /${String(value || '').replace(/\//g, '\\/')}/`;
            default:
                if (value === null || value === '') return `${field} = ""`;
                return `${field} = "${escaped}"`;
        }
    }
}

class YaraLBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        this.addComments = options.addComments !== false;
    }

    convert(sigmaRule) {
        const header = this.buildHeader(sigmaRule);
        const query = this._buildRule(sigmaRule);
        return [header, query].filter(p => p && p.trim() !== '').join('\n');
    }

    buildHeader(sigmaRule) {
        if (!this.addComments) return '';
        const lines = [];
        if (sigmaRule.title) lines.push(`# Title: ${sigmaRule.title}`);
        if (sigmaRule.level) lines.push(`# Level: ${sigmaRule.level}`);
        if (sigmaRule.description) lines.push(`# Description: ${sigmaRule.description.split('\n')[0]}`);
        lines.push('# Backend: Chronicle YARA-L');
        return lines.join('\n');
    }

    _buildRule(sigmaRule) {
        const ruleName = this._safeRuleName(sigmaRule.title || 'converted_sigma_rule');
        const condition = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        return [
            `rule ${ruleName} {`,
            '  meta:',
            `    source = "Sigma"`,
            '  events:',
            `    $e = ${condition}`,
            '  condition:',
            '    $e',
            '}'
        ].join('\n');
    }

    _safeRuleName(title) {
        return String(title)
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '_')
            .replace(/^_+|_+$/g, '') || 'converted_sigma_rule';
    }

    buildFieldCondition(node, logsource) {
        const field = COMMON_FIELD_MAP[node.field] || node.field;
        if (node.values.length === 1 && node.values[0] === null) {
            return `${field} = null`;
        }
        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(field, v, primaryMod, node.modifiers));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' and ')})` : parts[0];
        if (parts.length === 1) return parts[0];
        return `(${parts.join(' or ')})`;
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        if (primaryMod === 're' || primaryMod === 'regex') {
            return `${field} =~ "${this._escapeRegex(value)}"`;
        }
        const escaped = this._escapeString(value);
        switch (primaryMod) {
            case 'contains':   return `${field} contains "${escaped}"`;
            case 'startswith': return `${field} startswith "${escaped}"`;
            case 'endswith':   return `${field} endswith "${escaped}"`;
            default:
                if (value === null || value === '') return `${field} = null`;
                return `${field} = "${escaped}"`;
        }
    }

    _escapeString(value) {
        return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    _escapeRegex(value) {
        return String(value || '').replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        return values.map(v => `"${this._escapeString(v)}"`).join(' or ');
    }

    andExpr(a, b)  { return `(${a} and ${b})`; }
    orExpr(a, b)   { return `(${a} or ${b})`; }
    notExpr(a)     { return `not (${a})`; }
    wrapGroup(a)   { return `(${a})`; }
}

class Rapid7Backend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Rapid7 InsightIDR LEQL',
            commentPrefix: '//',
            fieldMap: {
                ...COMMON_FIELD_MAP,
                EventID: 'event_id',
                Image: 'process_name',
                CommandLine: 'command_line',
                User: 'actor',
                ComputerName: 'asset',
                DestinationIp: 'dest_ip',
                SourceIp: 'src_ip',
            },
        });
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null;
        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField}:null`;
        }
        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeLEQL(value);
        switch (primaryMod) {
            case 'contains':
                return `${field}:"*${escaped}*"`;
            case 'startswith':
                return `${field}:"${escaped}*"`;
            case 'endswith':
                return `${field}:"*${escaped}"`;
            default:
                if (value === null || value === '') return `${field}:null`;
                return `${field}:"${escaped}"`;
        }
    }

    _escapeLEQL(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        return values.map(v => `message:"${this._escapeLEQL(v)}"`).join(' OR ');
    }
}

class AnomaliBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Anomali ThreatStream',
            commentPrefix: '//',
            fieldMap: {
                ...COMMON_FIELD_MAP,
                DestinationIp: 'dest_ip',
                SourceIp: 'source_ip',
                QueryName: 'domain',
                Hashes: 'hash',
                md5: 'hash',
                sha256: 'hash',
            },
        });
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null;
        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField}:""`;
        }
        const primaryMod = node.modifiers[0];
        
        if (node.values.length === 1) {
            return this._buildSingleValue(mappedField, node.values[0], primaryMod);
        }
        
        const parts = node.values.map(v => this._stripQuotes(this._buildSingleValue(mappedField, v, primaryMod)));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        return `${mappedField}:(${parts.join('|')})`;
    }

    _stripQuotes(val) {
        return val.replace(/^[^"]*"(.*)"$/, '$1');
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeAnomali(value);
        switch (primaryMod) {
            case 'contains':
                return `${field}:"*${escaped}*"`;
            case 'startswith':
                return `${field}:"${escaped}*"`;
            case 'endswith':
                return `${field}:"*${escaped}"`;
            default:
                if (value === null || value === '') return `${field}:""`;
                return `${field}:"${escaped}"`;
        }
    }

    _escapeAnomali(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        return values.map(v => `"${this._escapeAnomali(v)}"`).join(' AND ');
    }
}

class LoggerBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Logger (Sumo-style)',
            commentPrefix: '//',
            fieldMap: {
                ...COMMON_FIELD_MAP,
                Image: 'process_name',
                CommandLine: 'command_line',
                User: 'user',
                ComputerName: 'host',
                EventID: 'event_id',
            },
        });
    }

    _buildQuery(sigmaRule) {
        const condition = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        return condition;
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null;
        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField}:""`;
        }
        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeLogger(value);
        switch (primaryMod) {
            case 'contains':
                return `${field}:*${escaped}*`;
            case 'startswith':
                return `${field}:${escaped}*`;
            case 'endswith':
                return `${field}:*${escaped}`;
            default:
                if (value === null || value === '') return `${field}:""`;
                return `${field}:"${escaped}"`;
        }
    }

    _escapeLogger(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        return values.map(v => `"${this._escapeLogger(v)}"`).join(' OR ');
    }
}

class ElastAlertBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'ElastAlert Lucene',
            commentPrefix: '//',
            fieldMap: {
                ...COMMON_FIELD_MAP,
                EventID: 'event_id',
                Image: 'process',
                CommandLine: 'command',
                User: 'user',
                ComputerName: 'host',
                DestinationIp: 'dest_ip',
                SourceIp: 'src_ip',
            },
        });
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null;
        if (node.values.length === 1 && node.values[0] === null) {
            return `NOT ${mappedField}:*`;
        }
        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeLucene(value);
        switch (primaryMod) {
            case 'contains':
                return `${field}:*${escaped}*`;
            case 'startswith':
                return `${field}:${escaped}*`;
            case 'endswith':
                return `${field}:*${escaped}`;
            default:
                if (value === null || value === '') return `NOT ${field}:*`;
                return `${field}:"${escaped}"`;
        }
    }

    _escapeLucene(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        return values.map(v => `"${this._escapeLucene(v)}"`).join(' OR ');
    }
}

class FortiSIEMBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'FortiSIEM Query',
            commentPrefix: '//',
            fieldMap: {
                ...COMMON_FIELD_MAP,
                EventID: 'EventType',
                Image: 'ProcessName',
                CommandLine: 'CommandLine',
                User: 'UserName',
                ComputerName: 'DevName',
                DestinationIp: 'DstIP',
                SourceIp: 'SrcIP',
            },
        });
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null;
        if (node.values.length === 1 && node.values[0] === null) {
            return `${mappedField}=""`;
        }
        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeFortisiem(value);
        switch (primaryMod) {
            case 'contains':
                return `${field}="*${escaped}*"`;
            case 'startswith':
                return `${field}="${escaped}*"`;
            case 'endswith':
                return `${field}="*${escaped}"`;
            default:
                if (value === null || value === '') return `${field}=""`;
                return `${field}="${escaped}"`;
        }
    }

    _escapeFortisiem(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        return values.map(v => `"${this._escapeFortisiem(v)}"`).join(' OR ');
    }
}

class TaniumBackend extends GenericQueryBackend {
    constructor(options = {}) {
        super({
            ...options,
            backendLabel: 'Tanium Query',
            commentPrefix: '//',
            fieldMap: {
                ...COMMON_FIELD_MAP,
                Image: 'Process Name',
                CommandLine: 'Command Line',
                User: 'User Name',
                ComputerName: 'Computer Name',
                TargetFilename: 'File Name',
                TargetObject: 'Registry Key',
            },
        });
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null;
        if (node.values.length === 1 && node.values[0] === null) {
            return `[${mappedField}] != ""`;
        }
        const primaryMod = node.modifiers[0];
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, primaryMod));
        if (node.useAll) return parts.length > 1 ? `(${parts.join(' AND ')})` : parts[0];
        if (parts.length === 1) return parts[0];
        return `(${parts.join(' OR ')})`;
    }

    _buildSingleValue(field, value, primaryMod) {
        const escaped = this._escapeTanium(value);
        switch (primaryMod) {
            case 'contains':
                return `[${field}] contains "${escaped}"`;
            case 'startswith':
                return `[${field}] like "${escaped}%"`;
            case 'endswith':
                return `[${field}] like "%${escaped}"`;
            default:
                if (value === null || value === '') return `[${field}] != ""`;
                return `[${field}] = "${escaped}"`;
        }
    }

    _escapeTanium(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        return values.map(v => `"${this._escapeTanium(v)}"`).join(' OR ');
    }
}

class SysmonXmlBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        this.addComments = options.addComments !== false;
    }

    convert(sigmaRule) {
        const refs = this._collectConditionRefs(sigmaRule?.detection?.conditionAst);
        const eventTag = this._mapLogsourceToEventTag(sigmaRule?.logsource || {});

        const includeRules = [];
        const excludeRules = [];

        const identifiers = sigmaRule?.detection?.identifiers || {};
        const names = Object.keys(identifiers);
        for (const name of names) {
            const node = identifiers[name];
            const key = String(name || '').toLowerCase();
            const inExclude = refs.exclude.has(key) || key.startsWith('filter');
            const target = inExclude ? excludeRules : includeRules;
            target.push(...this._identifierToXmlRules(node));
        }

        const lines = [];
        if (this.addComments) {
            lines.push('<!-- Generated by QueryCast: Sigma -> Sysmon XML -->');
            if (sigmaRule?.title) lines.push(`<!-- Title: ${this._xmlEscape(sigmaRule.title)} -->`);
            if (sigmaRule?.level) lines.push(`<!-- Level: ${this._xmlEscape(sigmaRule.level)} -->`);
        }

        lines.push('<Sysmon schemaversion="4.90">');
        lines.push('  <EventFiltering>');

        if (includeRules.length === 0 && excludeRules.length === 0) {
            lines.push(`    <${eventTag} onmatch="include">`);
            lines.push('      <!-- No concrete field filters could be generated from this Sigma rule. -->');
            lines.push(`    </${eventTag}>`);
        } else {
            if (includeRules.length > 0) {
                lines.push(`    <${eventTag} onmatch="include">`);
                includeRules.forEach(r => lines.push(`      ${r}`));
                lines.push(`    </${eventTag}>`);
            }
            if (excludeRules.length > 0) {
                lines.push(`    <${eventTag} onmatch="exclude">`);
                excludeRules.forEach(r => lines.push(`      ${r}`));
                lines.push(`    </${eventTag}>`);
            }
        }

        lines.push('  </EventFiltering>');
        lines.push('</Sysmon>');
        return lines.join('\n');
    }

    _collectConditionRefs(ast, negated = false, out = { include: new Set(), exclude: new Set() }) {
        if (!ast || typeof ast !== 'object') return out;
        if (ast.type === 'ref' && ast.name) {
            const name = String(ast.name).toLowerCase();
            if (negated) out.exclude.add(name);
            else out.include.add(name);
            return out;
        }
        if (ast.type === 'not') return this._collectConditionRefs(ast.expr, !negated, out);
        if (ast.type === 'and' || ast.type === 'or') {
            this._collectConditionRefs(ast.left, negated, out);
            this._collectConditionRefs(ast.right, negated, out);
            return out;
        }
        if ((ast.type === 'all_of' || ast.type === 'any_of') && Array.isArray(ast.identifiers)) {
            ast.identifiers.forEach(id => {
                const name = String(id).toLowerCase();
                if (negated) out.exclude.add(name);
                else out.include.add(name);
            });
        }
        return out;
    }

    _mapLogsourceToEventTag(logsource) {
        const category = String(logsource?.category || '').toLowerCase();
        switch (category) {
            case 'network_connection': return 'NetworkConnect';
            case 'file_event':
            case 'file_creation': return 'FileCreate';
            case 'registry_event':
            case 'registry_set':
            case 'registry_add':
            case 'registry_delete':
            case 'registry_rename': return 'RegistryEvent';
            case 'dns_query': return 'DnsQuery';
            case 'image_load': return 'ImageLoad';
            case 'driver_load': return 'DriverLoad';
            case 'pipe_created': return 'PipeEvent';
            case 'process_creation':
            default: return 'ProcessCreate';
        }
    }

    _identifierToXmlRules(node) {
        if (!node || typeof node !== 'object') return [];
        if (node.type === 'field_condition') return this._fieldConditionToXmlRules(node);
        if (node.type === 'keywords') {
            return (node.values || [])
                .filter(v => String(v || '').trim() !== '')
                .map(v => `<CommandLine condition="contains">${this._xmlEscape(String(v))}</CommandLine>`);
        }
        if (node.type === 'and_conditions' || node.type === 'or_conditions') {
            const out = [];
            (node.conditions || []).forEach(c => out.push(...this._identifierToXmlRules(c)));
            return out;
        }
        return [];
    }

    _fieldConditionToXmlRules(node) {
        const field = this._mapSigmaFieldToSysmonField(node.field);
        const values = (node.values || []).filter(v => v !== null && String(v).trim() !== '');
        if (!field || values.length === 0) return [];

        const mod = String(node.modifiers?.[0] || '').toLowerCase();
        if (mod === 're' || mod === 'regex') {
            return values.map(v => `<${field} condition="contains">${this._xmlEscape(String(v))}</${field}>`);
        }

        if ((mod === '' || mod === 'equals') && values.length > 1 && values.every(v => !/[?*]/.test(String(v)))) {
            return [`<${field} condition="is any">${this._xmlEscape(values.map(v => String(v)).join(';'))}</${field}>`];
        }

        return values.map(v => {
            const { condition, value } = this._mapValueToSysmonCondition(mod, String(v));
            return `<${field} condition="${condition}">${this._xmlEscape(value)}</${field}>`;
        });
    }

    _mapSigmaFieldToSysmonField(field) {
        const map = {
            EventID: 'EventID',
            Image: 'Image',
            CommandLine: 'CommandLine',
            ParentImage: 'ParentImage',
            ParentCommandLine: 'ParentCommandLine',
            User: 'User',
            ComputerName: 'Computer',
            TargetFilename: 'TargetFilename',
            TargetObject: 'TargetObject',
            QueryName: 'QueryName',
            SourceIp: 'SourceIp',
            SourcePort: 'SourcePort',
            DestinationIp: 'DestinationIp',
            DestinationPort: 'DestinationPort',
        };
        return map[field] || field;
    }

    _mapValueToSysmonCondition(mod, rawValue) {
        const value = String(rawValue || '');
        if (mod === 'contains') return { condition: 'contains', value };
        if (mod === 'startswith') return { condition: 'begin with', value };
        if (mod === 'endswith') return { condition: 'end with', value };

        const starts = value.startsWith('*');
        const ends = value.endsWith('*');
        const core = value.replace(/^\*/, '').replace(/\*$/, '');
        if (starts && ends) return { condition: 'contains', value: core };
        if (starts) return { condition: 'end with', value: core };
        if (ends) return { condition: 'begin with', value: core };
        return { condition: 'is', value };
    }

    _xmlEscape(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&apos;');
    }

    static parseQueryToSigma(xmlText) {
        const xml = String(xmlText || '').trim();
        if (!xml) throw new Error('No Sysmon XML content to convert.');

        const blockRe = /<(ProcessCreate|NetworkConnect|FileCreate|RegistryEvent|DnsQuery|ImageLoad|DriverLoad|PipeEvent)\b([^>]*)>([\s\S]*?)<\/\1>/gi;
        const includeMap = {};
        const excludeMap = {};
        let detectedEvent = 'ProcessCreate';
        let match;

        while ((match = blockRe.exec(xml)) !== null) {
            const tag = match[1];
            const attrs = match[2] || '';
            const body = match[3] || '';
            detectedEvent = detectedEvent || tag;

            const isExclude = /onmatch\s*=\s*"exclude"/i.test(attrs);
            const target = isExclude ? excludeMap : includeMap;
            const conditionRe = /<([A-Za-z0-9_]+)\s+condition\s*=\s*"([^"]+)"\s*>([\s\S]*?)<\/\1>/gi;
            let cm;
            while ((cm = conditionRe.exec(body)) !== null) {
                const sigmaField = SysmonXmlBackend._mapSysmonFieldToSigmaField(cm[1]);
                const condition = String(cm[2] || '').toLowerCase();
                const raw = SysmonXmlBackend._xmlUnescape(cm[3] || '').trim();
                if (!sigmaField || !raw) continue;

                if (condition === 'is any' || condition === 'contains any') {
                    const vals = raw.split(';').map(v => v.trim()).filter(Boolean);
                    vals.forEach(v => {
                        const out = SysmonXmlBackend._sysmonConditionToSigmaValue(condition, v);
                        const key = out.modifier ? `${sigmaField}|${out.modifier}` : sigmaField;
                        target[key] = target[key] || [];
                        target[key].push(out.value);
                    });
                    continue;
                }

                const out = SysmonXmlBackend._sysmonConditionToSigmaValue(condition, raw);
                const key = out.modifier ? `${sigmaField}|${out.modifier}` : sigmaField;
                target[key] = target[key] || [];
                target[key].push(out.value);
            }
        }

        const logsource = SysmonXmlBackend._eventTagToLogsource(detectedEvent);
        const lines = [];
        lines.push('title: "Imported Sysmon XML Rule"');
        lines.push(`id: "${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 10)}"`);
        lines.push('status: "experimental"');
        lines.push('description: "Auto-generated Sigma rule from Sysmon XML input"');
        lines.push('author: "QueryCast"');
        lines.push('logsource:');
        lines.push(`  product: ${logsource.product}`);
        lines.push(`  service: ${logsource.service}`);
        lines.push(`  category: ${logsource.category}`);
        lines.push('detection:');

        const includeFields = Object.keys(includeMap);
        const excludeFields = Object.keys(excludeMap);

        if (includeFields.length === 0 && excludeFields.length === 0) {
            const cleaned = xml.replace(/\s+/g, ' ').trim();
            lines.push('  selection:');
            lines.push('    keywords:');
            lines.push(`      - '${cleaned.replace(/'/g, "''")}'`);
            lines.push('  condition: selection');
            lines.push('level: medium');
            return lines.join('\n');
        }

        if (includeFields.length > 0) {
            lines.push('  selection:');
            includeFields.forEach(k => {
                lines.push(`    ${k}:`);
                Array.from(new Set(includeMap[k])).forEach(v => lines.push(`      - '${String(v).replace(/'/g, "''")}'`));
            });
        }

        if (excludeFields.length > 0) {
            lines.push('  filter_legit:');
            excludeFields.forEach(k => {
                lines.push(`    ${k}:`);
                Array.from(new Set(excludeMap[k])).forEach(v => lines.push(`      - '${String(v).replace(/'/g, "''")}'`));
            });
        }

        if (includeFields.length > 0 && excludeFields.length > 0) lines.push('  condition: selection and not filter_legit');
        else if (includeFields.length > 0) lines.push('  condition: selection');
        else lines.push('  condition: not filter_legit');

        lines.push('level: medium');
        return lines.join('\n');
    }

    static _mapSysmonFieldToSigmaField(field) {
        const f = String(field || '').toLowerCase();
        const map = {
            eventid: 'EventID',
            image: 'Image',
            commandline: 'CommandLine',
            parentimage: 'ParentImage',
            parentcommandline: 'ParentCommandLine',
            user: 'User',
            computer: 'ComputerName',
            targetfilename: 'TargetFilename',
            targetobject: 'TargetObject',
            queryname: 'QueryName',
            sourceip: 'SourceIp',
            sourceport: 'SourcePort',
            destinationip: 'DestinationIp',
            destinationport: 'DestinationPort',
        };
        return map[f] || field;
    }

    static _sysmonConditionToSigmaValue(condition, value) {
        const c = String(condition || '').toLowerCase();
        if (c === 'contains' || c === 'contains any') return { modifier: 'contains', value };
        if (c === 'begin with') return { modifier: 'startswith', value };
        if (c === 'end with') return { modifier: 'endswith', value };
        return { modifier: '', value };
    }

    static _eventTagToLogsource(tag) {
        const t = String(tag || '').toLowerCase();
        const map = {
            processcreate: { product: 'windows', service: 'sysmon', category: 'process_creation' },
            networkconnect: { product: 'windows', service: 'sysmon', category: 'network_connection' },
            filecreate: { product: 'windows', service: 'sysmon', category: 'file_event' },
            registryevent: { product: 'windows', service: 'sysmon', category: 'registry_event' },
            dnsquery: { product: 'windows', service: 'sysmon', category: 'dns_query' },
            imageload: { product: 'windows', service: 'sysmon', category: 'image_load' },
            driverload: { product: 'windows', service: 'sysmon', category: 'driver_load' },
            pipeevent: { product: 'windows', service: 'sysmon', category: 'pipe_created' },
        };
        return map[t] || { product: 'windows', service: 'sysmon', category: 'process_creation' };
    }

    static _xmlUnescape(value) {
        return String(value || '')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .replace(/&apos;/g, "'")
            .replace(/&amp;/g, '&');
    }
}
