/**
 * splunk.js - Sigma to Splunk SPL backend
 */
'use strict';

class SplunkBackend extends BaseBackend {
    constructor(options = {}) {
        super(options);
        this.addComments = options.addComments !== false;
    }

    buildHeader(sigmaRule) {
        const ls = sigmaRule.logsource;
        const indexLine = this._buildIndexFilter(ls);
        if (!this.addComments) return indexLine;
        const lines = [];
        if (sigmaRule.title)       lines.push(' * Title: ' + sigmaRule.title);
        if (sigmaRule.level)       lines.push(' * Level: ' + sigmaRule.level);
        if (sigmaRule.description) lines.push(' * Description: ' + sigmaRule.description.split('\n')[0]);
        if (lines.length === 0) return indexLine;
        return '/*\n' + lines.join('\n') + '\n */\n' + indexLine;
    }

    _buildIndexFilter(logsource) {
        const product  = (logsource.product  || '').toLowerCase();
        const category = (logsource.category || '').toLowerCase();
        const service  = (logsource.service  || '').toLowerCase();
        if (product === 'windows') {
            if (service === 'sysmon' || ['network_connection','file_event','registry_event','image_load','dns_query','pipe_created'].includes(category)) {
                return 'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"';
            }
            if (category === 'process_creation') {
                return 'source="WinEventLog:Security" OR source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"';
            }
            if (service === 'security')     return 'source="WinEventLog:Security"';
            if (service === 'system')       return 'source="WinEventLog:System"';
            if (service === 'application')  return 'source="WinEventLog:Application"';
            return 'index=wineventlog';
        }
        if (product === 'linux') return service ? 'source="' + service + '"' : 'index=linux_logs';
        if (product === 'macos') return 'index=macos_logs';
        return '';
    }

    _mapField(fieldName, logsource) {
        return FieldMaps.mapField(fieldName, logsource, 'splunk', true);
    }

    buildFieldCondition(node, logsource) {
        const mappedField = this._mapField(node.field, logsource);
        if (mappedField === null) return null; // unsupported field – caller will skip and warn
        if (node.values.length === 1 && node.values[0] === null) return 'NOT ' + mappedField + '=*';
        const parts = node.values.map(v => this._buildSingleValue(mappedField, v, node.modifiers[0], node.modifiers));
        if (node.useAll) {
            const combined = parts.join(' ');
            return parts.length > 1 ? '(' + combined + ')' : combined;
        }
        if (parts.length === 1) return parts[0];
        return '(' + parts.join(' OR ') + ')';
    }

    _buildSingleValue(field, value, primaryMod, allMods) {
        if (primaryMod === 're' || primaryMod === 'regex') {
            return field + '=~"' + this._escapeSplunkRegex(value) + '"';
        }
        if (primaryMod === 'cidr') return field + '="' + value + '"';
        if (allMods && (allMods.includes('base64') || allMods.includes('base64offset'))) {
            try {
                const decoded = atob(value);
                return field + '="*' + this._escapeSplunkValue(decoded) + '*"';
            } catch(e) {
                return field + '="' + this._escapeSplunkValue(value) + '"';
            }
        }
        const escaped = this._escapeSplunkValue(value);
        switch (primaryMod) {
            case 'contains':   return field + '="*' + escaped + '*"';
            case 'startswith': return field + '="' + escaped + '*"';
            case 'endswith':   return field + '="*' + escaped + '"';
            default:
                if (value === null || value === '') return 'NOT ' + field + '=*';
                return field + '="' + escaped + '"';
        }
    }

    _escapeSplunkValue(value) {
        if (value === null || value === undefined) return '';
        return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    _escapeSplunkRegex(value) {
        return String(value).replace(/"/g, '\\"');
    }

    buildKeywords(values, logsource) {
        const escaped = values.map(v => '"' + this._escapeSplunkValue(v) + '"');
        return escaped.length === 1 ? escaped[0] : '(' + escaped.join(' OR ') + ')';
    }

    andExpr(a, b)  { return a + ' ' + b; }
    orExpr(a, b)   { return '(' + a + ' OR ' + b + ')'; }
    notExpr(a)     { return 'NOT ' + a; }
    wrapGroup(a)   { return '(' + a + ')'; }
}
