/**
 * operators-registry.js
 * Defines all available operators for QueryCast.
 * Each operator describes its metadata and how to run.
 */
'use strict';

const OperatorsRegistry = (() => {

    function _randHex(len) {
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const bytes = new Uint8Array(Math.ceil(len / 2));
            crypto.getRandomValues(bytes);
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, len);
        }
        let out = '';
        while (out.length < len) {
            out += Math.floor(Math.random() * 16).toString(16);
        }
        return out.slice(0, len);
    }

    function _timeUuid() {
        // UUIDv7-style time-ordered ID
        const msHex = Date.now().toString(16).padStart(12, '0').slice(-12);
        const timeLow = msHex.slice(0, 8);
        const timeMid = msHex.slice(8, 12);
        const timeHiAndVersion = `7${_randHex(3)}`;
        const variantNibble = ['8', '9', 'a', 'b'][Math.floor(Math.random() * 4)];
        const clockSeq = `${variantNibble}${_randHex(3)}`;
        const node = _randHex(12);
        return `${timeLow}-${timeMid}-${timeHiAndVersion}-${clockSeq}-${node}`;
    }

    function _escapeYamlDoubleQuoted(value) {
        return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    }

    function _normalizeImportedValue(value) {
        return String(value || '')
            .replace(/\\"/g, '"')
            .replace(/\\\\/g, '\\');
    }

    function _detectInputFormat(input) {
        const text = String(input || '');
        const lower = text.toLowerCase();

        if (/^\s*(title|id|logsource|detection)\s*:/m.test(text)) return 'sigma';
        if (/\|\s*where\b/i.test(text) || /\bstartswith\b|\bcontains\b|\bin~\b/i.test(text)) return 'kql';
        if (/\bsource\s*=\s*\w+/i.test(text) && /\|\s*where\b/i.test(text)) return 'ppl';
        if (/\bdataset\s*=\s*\w+/i.test(text) || /\|\s*filter\b/i.test(text)) return 'xql';
        if (/\{[^}]*\}\s*\|\s*(json|=~|=|!~|!=)/i.test(text) || /\b\|=\b|\b\|~\b/.test(text)) return 'logql';
        if (/\bfields\s+@timestamp\b|\|\s*filter\s+/i.test(text)) return 'cwli';
        if (/\bprincipal\.|\bmetadata\.log_type\b|\bnocase\b/i.test(lower)) return 'udm';
        if (/<Sysmon\b|<(ProcessCreate|NetworkConnect|FileCreate|RegistryEvent|DnsQuery|ImageLoad|DriverLoad|PipeEvent)\b/i.test(text)) return 'sysmonxml';
        if (/\b(select\s+\*\s+from\s+events\s+where)\b/i.test(text) && /(\bip\.(src|dst)\b|\bdns\.query\b|\bparent\.process\b|\bevent\.id\b)/i.test(text)) return 'nwql';
        if (/\bselect\s+.+\s+from\s+/i.test(text)) return 'aql';
        if (/\bprocess\s+where\b/i.test(text)) return 'eql';
        if (/\bindex\s*=|\bsource\s*=|\bEventCode\s*=|\w+\s*=\s*"[^"]+"/i.test(text)) return 'splunk';
        // Carbon Black: process_name, cmdline, parent_name, user_name, md5, sha256, etc.
        if (/(process_name|cmdline|parent_name|user_name|md5|sha256|registry_path|ipv4|port|dns_name)\s*:/i.test(text)) return 'cb';
        // Rapid7 InsightIDR LEQL: event_id IN [...], actor:"...", action:"..."
        if (/\bevent_id\s+(IN|in)\s*\[|\bactor\s*:\s*"|\baction\s*:\s*"/.test(text)) return 'rapid7';
        // Anomali ThreatStream: source_ip:, dest_ip:, threat_type:(val|val)
        if (/(source_ip|dest_ip|threat_type)\s*:\s*|threat_type\s*:\s*\([^)]*\|/.test(text)) return 'anomali';
        // Logger (Sumo-style): _source, _sourceHost, _raw, _collector
        if (/(_source|_sourceHost|_raw|_collector|_severity)\s*:|error\s+AND\s+_sourceHost/.test(text)) return 'logger';
        // ElastAlert Lucene: level:ERROR, host:(prod-* OR staging-*) with specific tag patterns
        if (/\blevel\s*:\s*(ERROR|WARN|INFO|DEBUG)|\bhost\s*:\s*\([^)]*\*[^)]*\)|\btags\s*:\s*\*/.test(text)) return 'elastalert';
        // FortiSIEM: EventType="Attack", EventSeverity>=5, DevIP="10.0.*"
        if (/(EventType|EventSeverity|DevIP|SrcIP|DstIP|UserName)\s*[=!<>]+\s*"/.test(text)) return 'fortisiem';
        // Tanium: [Computer Name] like "prod%", [Process Name] = "svchost.exe"
        if (/\[[A-Za-z\s]+\]\s*(=|!=|like|AND|OR)/.test(text)) return 'tanium';
        if (/\w+\s*:\s*(\*|"|\/|\w)/.test(text)) return 'elastic';
        if (/\brule\s+[a-z0-9_]+\s*\{/i.test(lower)) return 'yaral';

        return 'query';

    }

    function _stripQueryComments(input) {
        const text = String(input || '');

        // Remove block comments first to avoid line-level false positives.
        const withoutBlocks = text.replace(/\/\*[\s\S]*?\*\//g, '\n');

        return withoutBlocks
            .split(/\r?\n/)
            .map(l => l.trim())
            .filter(l => l && !l.startsWith('//') && !l.startsWith('#') && !l.startsWith('--'))
            .join('\n');
    }

    function _inferSigmaModifier(values) {
        if (!values || values.length === 0) return { modifier: 'contains', cleaned: [] };

        const allContains = values.every(v => v.startsWith('*') && v.endsWith('*') && v.length >= 2);
        if (allContains) return { modifier: 'contains', cleaned: values.map(v => v.slice(1, -1)) };

        const allStarts = values.every(v => !v.startsWith('*') && v.endsWith('*'));
        if (allStarts) return { modifier: 'startswith', cleaned: values.map(v => v.slice(0, -1)) };

        const allEnds = values.every(v => v.startsWith('*') && !v.endsWith('*'));
        if (allEnds) return { modifier: 'endswith', cleaned: values.map(v => v.slice(1)) };

        const allExact = values.every(v => !v.includes('*') && !v.includes('?'));
        if (allExact) return { modifier: '', cleaned: values };

        return { modifier: 'contains', cleaned: values };
    }

    function _buildSigmaBlock(name, fieldMap, indent) {
        const lines = [];
        lines.push(`${' '.repeat(indent)}${name}:`);

        const fields = Object.keys(fieldMap);
        for (const field of fields) {
            const vals = Array.from(new Set(fieldMap[field]));
            const { modifier, cleaned } = _inferSigmaModifier(vals);
            const key = modifier ? `${field}|${modifier}` : field;
            lines.push(`${' '.repeat(indent + 2)}${key}:`);
            cleaned.forEach(v => lines.push(`${' '.repeat(indent + 4)}- '${String(v).replace(/'/g, "''")}'`));
        }

        return lines;
    }

    function _unquoteQueryValue(raw) {
        const text = String(raw || '').trim();
        if (!text) return '';
        if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
            return text.slice(1, -1)
                .replace(/\\"/g, '"')
                .replace(/\\'/g, "'")
                .replace(/\\\\/g, '\\');
        }
        return text;
    }

    function _normalizeSourceQueryForExtraction(input, sourceFormat) {
        const raw = _stripQueryComments(input).trim();
        if (!raw) return '';

        if (sourceFormat === 'elastic' || sourceFormat === 'eql') {
            // Normalize Lucene-style contains with spaces: field:* token * -> field:"*token*"
            return raw.replace(
                /([A-Za-z0-9_.-]+):\*\s+([^()]+?)\s+\*(?=\s+(AND|OR|and|or)\b|\)|$)/g,
                (m, field, inner) => `${field}:"*${String(inner).trim()}*"`
            );
        }

        if (sourceFormat === 'aql' || sourceFormat === 'vql' || sourceFormat === 'eql' || sourceFormat === 'nwql') {
            const whereMatch = raw.match(/\bwhere\b([\s\S]*)/i);
            return whereMatch ? whereMatch[1].trim() : raw;
        }

        if (sourceFormat === 'arcsight' || sourceFormat === 'oql' || sourceFormat === 'sumoql') {
            const whereMatch = raw.match(/\bwhere\b([\s\S]*)/i);
            return whereMatch ? whereMatch[1].trim() : raw;
        }

        if (sourceFormat === 'ppl' || sourceFormat === 'xql' || sourceFormat === 'cwli') {
            const pipeMatch = raw.match(/\|\s*(where|filter)\s+([\s\S]*)/i);
            return pipeMatch ? pipeMatch[2].trim() : raw;
        }

        if (sourceFormat === 'graylog') {
            return raw
                .replace(/\bmessage\s*:/gi, 'message contains ')
                .replace(/\bfull_message\s*:/gi, 'full_message contains ');
        }

        if (sourceFormat === 'ddql') {
            // Datadog often prefixes facets with @
            return raw.replace(/@([A-Za-z0-9_.-]+)\s*:/g, '$1:');
        }

        if (sourceFormat === 'logql') {
            const pipeMatch = raw.match(/\|\s*(json|logfmt)?\s*\|\s*([\s\S]*)/i);
            const normalized = pipeMatch ? pipeMatch[2].trim() : raw;
            return normalized.replace(/\|=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s|]+)/g, ' message contains $1');
        }

        if (sourceFormat === 'logscale') {
            return raw
                .replace(/\s*\|\s*/g, ' AND ')
                .replace(/\b(field|select|table)\s+[^\s]+/gi, '')
                .trim();
        }

        if (sourceFormat === 'yaral') {
            const cond = raw.match(/\bcondition\s*:\s*([\s\S]*)$/i);
            return cond ? cond[1].trim() : raw;
        }

        if (sourceFormat === 'logscale') {
            const afterPipe = raw.split('|').slice(1).join(' | ').trim();
            return afterPipe || raw;
        }

        return raw;
    }

    function _normalizeFieldNameForSigma(field, sourceFormat) {
        const f = String(field || '').trim();
        if (!f) return '';

        const generic = {
            process_name: 'Image',
            processname: 'Image',
            image: 'Image',
            file_path: 'Image',
            process_executable: 'Image',
            process_executable_path: 'Image',

            commandline: 'CommandLine',
            command_line: 'CommandLine',
            cmdline: 'CommandLine',
            process_command_line: 'CommandLine',

            parentimage: 'ParentImage',
            parent_name: 'ParentImage',
            parent_process_name: 'ParentImage',
            process_parent_executable: 'ParentImage',

            user: 'User',
            user_name: 'User',
            username: 'User',
            accountname: 'User',

            sha256: 'Hashes.SHA256',
            md5: 'Hashes.MD5',

            eventid: 'EventID',
            event_id: 'EventID',
            eventcode: 'EventID',

            targetobject: 'TargetObject',
            registry_path: 'TargetObject',

            queryname: 'QueryName',
            dns_name: 'QueryName',
            dns_query: 'QueryName',

            destinationip: 'DestinationIp',
            dest_ip: 'DestinationIp',
            remoteip: 'DestinationIp',

            destinationport: 'DestinationPort',
            dest_port: 'DestinationPort',
            remoteport: 'DestinationPort',
        };

        const normalized = f
            .replace(/^-/, '')
            .replace(/^@/, '')
            .replace(/^\[/, '')
            .replace(/\]$/, '')
            .toLowerCase();
        if (generic[normalized]) return generic[normalized];

        const sourceSpecific = {
            kql: {
                newprocessname: 'Image',
                folderpath: 'Image',
                initiatingprocessfolderpath: 'ParentImage',
                processfilename: 'Image',
                processcommandline: 'CommandLine',
                parentprocessname: 'ParentImage',
                accountname: 'User',
                subjectusername: 'User',
            },
            vql: {
                image: 'Image',
                commandline: 'CommandLine',
                parentimage: 'ParentImage',
                user: 'User',
                computer: 'ComputerName',
            },
            elastic: {
                'process.executable': 'Image',
                'process.command_line': 'CommandLine',
                'process.parent.executable': 'ParentImage',
                'user.name': 'User',
                'host.name': 'ComputerName',
                'process.hash.sha256': 'Hashes.SHA256',
                'process.hash.md5': 'Hashes.MD5',
            },
            eql: {
                'process.executable': 'Image',
                'process.command_line': 'CommandLine',
                'process.parent.executable': 'ParentImage',
                'user.name': 'User',
            },
            xql: {
                actor_process_image_path: 'Image',
                actor_process_command_line: 'CommandLine',
                causality_actor_process_image_path: 'ParentImage',
                actor_primary_username: 'User',
                agent_hostname: 'ComputerName',
            },
            s1ql: {
                srcprocimagepath: 'Image',
                srcproccmdline: 'CommandLine',
                srcprocparentname: 'ParentImage',
                srcprocuser: 'User',
                endpointname: 'ComputerName',
                sha256: 'Hashes.SHA256',
                md5: 'Hashes.MD5',
            },
            aql: {
                eventcode: 'EventID',
                image: 'Image',
                commandline: 'CommandLine',
                parentimage: 'ParentImage',
                username: 'User',
                computername: 'ComputerName',
            },
            nwql: {
                process: 'Image',
                command: 'CommandLine',
                'parent.process': 'ParentImage',
                user: 'User',
                host: 'ComputerName',
                'ip.src': 'SourceIp',
                'port.src': 'SourcePort',
                'ip.dst': 'DestinationIp',
                'port.dst': 'DestinationPort',
                'dns.query': 'QueryName',
                filename: 'TargetFilename',
                'registry.key': 'TargetObject',
                'event.id': 'EventID',
            },
            ppl: {
                process_name: 'Image',
                command_line: 'CommandLine',
                parent_process_name: 'ParentImage',
                user_name: 'User',
                host: 'ComputerName',
            },
            oql: {
                processname: 'Image',
                process_name: 'Image',
                commandline: 'CommandLine',
                parentprocessname: 'ParentImage',
                username: 'User',
                hostname: 'ComputerName',
            },
            arcsight: {
                deviceprocessname: 'Image',
                processname: 'Image',
                devicecustomstring1: 'CommandLine',
                destinationusername: 'User',
                sourceaddress: 'SourceIp',
                destinationaddress: 'DestinationIp',
            },
            ddql: {
                message: 'CommandLine',
                service: 'Product',
                host: 'ComputerName',
                usr_name: 'User',
                user_name: 'User',
                process_name: 'Image',
                cmdline: 'CommandLine',
                parent_name: 'ParentImage',
            },
            udm: {
                'principal.process.file.full_path': 'Image',
                'principal.process.command_line': 'CommandLine',
                'principal.user.userid': 'User',
                'principal.hostname': 'ComputerName',
            },
            graylog: {
                source: 'ComputerName',
                message: 'CommandLine',
                full_message: 'CommandLine',
                image: 'Image',
                commandline: 'CommandLine',
                parentimage: 'ParentImage',
            },
            sumoql: {
                process_name: 'Image',
                command_line: 'CommandLine',
                parent_process_name: 'ParentImage',
                user_name: 'User',
                host: 'ComputerName',
            },
            logscale: {
                imagefilename: 'Image',
                commandline: 'CommandLine',
                parentbasefilename: 'ParentImage',
                aid: 'ComputerName',
                username: 'User',
            },
            logql: {
                message: 'CommandLine',
                filename: 'Image',
                host: 'ComputerName',
            },
            cwli: {
                process_name: 'Image',
                process_name_path: 'Image',
                command_line: 'CommandLine',
                parent_process_name: 'ParentImage',
                user: 'User',
                host: 'ComputerName',
            },
            yaral: {
                'principal.process.file.full_path': 'Image',
                'principal.process.command_line': 'CommandLine',
                'principal.user.userid': 'User',
                'principal.hostname': 'ComputerName',
            }
        };

        const formatMap = sourceSpecific[sourceFormat] || {};
        return formatMap[normalized] || f;
    }

    function _valueToSigmaWildcard(value, opRaw) {
        const op = String(opRaw || '').toLowerCase();
        const v = String(value || '');

        if (op === 'contains' || op === 'has' || op === 'in~') return `*${v}*`;
        if (op === 'startswith' || op === 'starts_with') return `${v}*`;
        if (op === 'endswith' || op === 'ends_with') return `*${v}`;
        if (op === 'like') {
            const startsPct = v.startsWith('%');
            const endsPct = v.endsWith('%');
            const core = v.replace(/^%/, '').replace(/%$/, '');
            if (startsPct && endsPct) return `*${core}*`;
            if (startsPct) return `*${core}`;
            if (endsPct) return `${core}*`;
            return core;
        }

        if (op === ':' || op === '=' || op === '==' || op === '=~' || op === 'matches') {
            const startsStar = v.startsWith('*');
            const endsStar = v.endsWith('*');
            if (startsStar && endsStar) return `*${v.slice(1, -1)}*`;
            if (startsStar) return `*${v.slice(1)}`;
            if (endsStar) return `${v.slice(0, -1)}*`;
            return v;
        }

        return v;
    }

    function _extractFieldComparisons(raw, sourceFormat) {
        const text = _normalizeSourceQueryForExtraction(raw, sourceFormat);
        if (!text) return [];

        const comparisons = [];
        const patterns = [
            /([@A-Za-z0-9_.-]+)\s*(==|=|!=|<>|:|=~)\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\/[^\/]+\/|[^\s()]+)/g,
            /([@A-Za-z0-9_.-]+)\s+(contains|startswith|endswith|starts_with|ends_with|has|like|matches|in~)\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s()]+)/gi
        ];

        const skipFieldsByFormat = {
            aql: ['events'],
            ppl: ['source', 'logs'],
            xql: ['dataset', 'event_type', 'event_sub_type'],
            logql: ['json', 'logfmt'],
            ddql: ['service'],
            cwli: ['@timestamp']
        };
        const skip = new Set((skipFieldsByFormat[sourceFormat] || []).map(v => v.toLowerCase()));

        patterns.forEach((regex) => {
            let m;
            while ((m = regex.exec(text)) !== null) {
                const fieldRaw = m[1];
                const opRaw = m[2];
                const valueRaw = m[3];

                const leftContext = text.slice(Math.max(0, m.index - 16), m.index);
                const hasNotPrefix = /\bnot\s*$/i.test(leftContext) || /-\s*$/.test(leftContext);
                const isNotEq = opRaw === '!=' || opRaw === '<>';
                const hasNegFieldPrefix = /^-/.test(String(fieldRaw));
                const negated = hasNotPrefix || isNotEq || hasNegFieldPrefix;

                const sigmaField = _normalizeFieldNameForSigma(fieldRaw, sourceFormat);
                const value = _unquoteQueryValue(valueRaw).trim();
                if (!sigmaField || !value) continue;
                if (skip.has(String(fieldRaw).replace(/^@/, '').toLowerCase())) continue;

                const wildcardValue = _valueToSigmaWildcard(value, opRaw);
                if (!wildcardValue || wildcardValue.replace(/\*/g, '').trim() === '') continue;

                comparisons.push({
                    field: sigmaField,
                    value: wildcardValue,
                    negated,
                });
            }
        });

        return comparisons;
    }

    function _toSigmaFromGenericQuery(input, sourceFormat) {
        const cleaned = _stripQueryComments(input);
        const lines = cleaned
            .split(/\r?\n/)
            .map(l => l.trim())
            .filter(Boolean)
            .slice(0, 100);
        const combined = lines.join(' ');

        const comparisons = _extractFieldComparisons(combined, sourceFormat);

        const positiveFields = {};
        const negativeFields = {};
        comparisons.forEach((c) => {
            const target = c.negated ? negativeFields : positiveFields;
            target[c.field] = target[c.field] || [];
            target[c.field].push(c.value);
        });

        const output = [];
        output.push(`title: "${_escapeYamlDoubleQuoted(`Imported ${sourceFormat.toUpperCase()} Query`)}"`);
        output.push(`id: "${_timeUuid()}"`);
        output.push(`status: "${_escapeYamlDoubleQuoted('experimental')}"`);
        output.push(`description: "${_escapeYamlDoubleQuoted(`Auto-generated Sigma rule from ${sourceFormat.toUpperCase()} query input`)}"`);
        output.push(`author: "${_escapeYamlDoubleQuoted('QueryCast')}"`);
        output.push('logsource:');
        output.push('  product: windows');
        output.push('  category: process_creation');
        output.push('detection:');

        const hasSelection = Object.keys(positiveFields).length > 0;
        const hasFilter = Object.keys(negativeFields).length > 0;

        if (hasSelection) output.push(..._buildSigmaBlock('selection', positiveFields, 2));
        if (hasFilter) output.push(..._buildSigmaBlock('filter_legit', negativeFields, 2));

        if (!hasSelection && !hasFilter) {
            const keywordLines = lines.slice(0, 20);
            output.push('  selection:');
            output.push('    keywords:');
            keywordLines.forEach(k => output.push(`      - '${_normalizeImportedValue(String(k)).replace(/'/g, "''")}'`));
            output.push('  condition: selection');
        } else if (hasSelection && hasFilter) {
            output.push('  condition: selection and not filter_legit');
        } else if (hasSelection) {
            output.push('  condition: selection');
        } else {
            output.push('  condition: not filter_legit');
        }

        output.push('level: medium');
        return output.join('\n');
    }

    function _toSigmaFromSplunk(input) {
        const cleanedQuery = _stripQueryComments(input);
        if (/(process_name|process_cmdline|cmdline|parent_name|user_name|md5|sha256|registry_path|ipv4|port|dns_name)\s*:/i.test(cleanedQuery)) {
            // User likely provided a Carbon Black query while using Splunk To Sigma.
            // Delegate to the specialized Carbon Black reverse parser instead of
            // producing a generic keywords fallback.
            return _toSigmaFromQuery(cleanedQuery, 'cb');
        }

        const lines = cleanedQuery
            .split(/\r?\n/)
            .map(l => l.trim())
            .filter(Boolean)
            .slice(0, 100);

        const combined = lines.join(' ');

        const positivePart = combined.replace(/\bNOT\s*\(([^)]+)\)/gi, ' ');
        const negativeMatches = [];
        const notGroupRegex = /\bNOT\s*\(([^)]+)\)/gi;
        let ng;
        while ((ng = notGroupRegex.exec(combined)) !== null) {
            negativeMatches.push(ng[1]);
        }

        const pairRegex = /([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"/g;
        const positiveFields = {};
        let m;
        while ((m = pairRegex.exec(positivePart)) !== null) {
            const field = m[1];
            const value = _normalizeImportedValue(m[2]);
            if (field.toLowerCase() === 'source' || field.toLowerCase() === 'index') continue;
            positiveFields[field] = positiveFields[field] || [];
            positiveFields[field].push(value);
        }

        const negativeFields = {};
        negativeMatches.forEach(group => {
            let nm;
            while ((nm = pairRegex.exec(group)) !== null) {
                const field = nm[1];
                const value = _normalizeImportedValue(nm[2]);
                negativeFields[field] = negativeFields[field] || [];
                negativeFields[field].push(value);
            }
        });

        const output = [];
        output.push(`title: "${_escapeYamlDoubleQuoted('Imported SPLUNK Query')}"`);
        output.push(`id: "${_timeUuid()}"`);
        output.push(`status: "${_escapeYamlDoubleQuoted('experimental')}"`);
        output.push(`description: "${_escapeYamlDoubleQuoted('Auto-generated Sigma rule from SPLUNK query input')}"`);
        output.push(`author: "${_escapeYamlDoubleQuoted('QueryCast')}"`);
        output.push('logsource:');
        output.push('  product: windows');
        output.push('  category: process_creation');
        output.push('detection:');

        const hasSelection = Object.keys(positiveFields).length > 0;
        const hasFilter = Object.keys(negativeFields).length > 0;

        if (hasSelection) {
            output.push(..._buildSigmaBlock('selection', positiveFields, 2));
        }

        if (hasFilter) {
            output.push(..._buildSigmaBlock('filter_legit', negativeFields, 2));
        }

        if (!hasSelection && !hasFilter) {
            const keywordLines = lines.slice(0, 20);
            output.push('  selection:');
            output.push('    keywords:');
            keywordLines.forEach(k => output.push(`      - '${_normalizeImportedValue(String(k)).replace(/'/g, "''")}'`));
            output.push('  condition: selection');
        } else if (hasSelection && hasFilter) {
            output.push('  condition: selection and not filter_legit');
        } else if (hasSelection) {
            output.push('  condition: selection');
        } else {
            output.push('  condition: not filter_legit');
        }

        output.push('level: medium');
        return output.join('\n');
    }

    function _toSigmaFromQuery(input, sourceFormat) {
        if (sourceFormat === 'splunk') {
            return _toSigmaFromSplunk(input);
        }

        // Use specialized parser for Elasticsearch Lucene queries
        if (sourceFormat === 'elastic') {
            const raw = _stripQueryComments(input).trim();
            if (!raw) throw new Error('No Elastic query to convert.');
            const parsed = ElasticLuceneBackend.parseQueryToSigma(raw);
            if (!parsed.includes('title:')) {
                const lines = parsed.split('\n');
                lines.splice(0, 0, `title: "Imported Elastic Query"\nid: "${_timeUuid()}"\nstatus: experimental\nauthor: QueryCast`);
                return lines.join('\n');
            }
            return parsed;
        }

        // Use specialized parser for Carbon Black queries
        if (sourceFormat === 'cb') {
            const raw = _stripQueryComments(input).trim();
            if (!raw) throw new Error('No Carbon Black query to convert.');
            const parsed = CarbonBlackBackend.parseQueryToSigma(raw);
            // Add title, id, status if not present
            if (!parsed.includes('title:')) {
                const lines = parsed.split('\n');
                lines.splice(0, 0, `title: "Imported Carbon Black Query"\nid: "${_timeUuid()}"\nstatus: experimental\nauthor: QueryCast`);
                return lines.join('\n');
            }
            return parsed;
        }

        // Use specialized parser for Microsoft KQL queries
        if (sourceFormat === 'kql') {
            const raw = _stripQueryComments(input).trim();
            if (!raw) throw new Error('No KQL query to convert.');
            const parsed = KqlBackend.parseQueryToSigma(raw);
            if (!parsed.includes('title:')) {
                const lines = parsed.split('\n');
                lines.splice(0, 0, `title: "Imported KQL Query"\nid: "${_timeUuid()}"\nstatus: experimental\nauthor: QueryCast`);
                return lines.join('\n');
            }
            return parsed;
        }

        // Use specialized parser for Velociraptor VQL queries
        if (sourceFormat === 'vql') {
            const raw = _stripQueryComments(input).trim();
            if (!raw) throw new Error('No VQL query to convert.');
            const parsed = VqlBackend.parseQueryToSigma(raw);
            if (!parsed.includes('title:')) {
                const lines = parsed.split('\n');
                lines.splice(0, 0, `title: "Imported VQL Query"\nid: "${_timeUuid()}"\nstatus: experimental\nauthor: QueryCast`);
                return lines.join('\n');
            }
            return parsed;
        }

        // Use specialized parser for Sysmon XML snippets
        if (sourceFormat === 'sysmonxml') {
            const raw = _stripQueryComments(input).trim();
            if (!raw) throw new Error('No Sysmon XML content to convert.');
            return SysmonXmlBackend.parseQueryToSigma(raw);
        }

        // Generic structured extraction for the remaining query syntaxes.
        // Falls back to keywords internally when no field comparisons can be extracted.
        return _toSigmaFromGenericQuery(input, sourceFormat);
    }

    function _identifierHasSignal(node) {
        if (!node || typeof node !== 'object') return false;

        if (node.type === 'field_condition') {
            if (!Array.isArray(node.values) || node.values.length === 0) return false;
            return node.values.some(v => v === null || String(v).trim() !== '');
        }

        if (node.type === 'keywords') {
            if (!Array.isArray(node.values) || node.values.length === 0) return false;
            return node.values.some(v => String(v || '').trim() !== '');
        }

        if (node.type === 'and_conditions' || node.type === 'or_conditions') {
            return Array.isArray(node.conditions)
                && node.conditions.some(c => _identifierHasSignal(c));
        }

        return false;
    }

    function _collectConditionRefs(ast, outSet) {
        if (!ast || typeof ast !== 'object') return;

        if (ast.type === 'ref' && ast.name) {
            outSet.add(String(ast.name).toLowerCase());
            return;
        }

        if (ast.type === 'and' || ast.type === 'or') {
            _collectConditionRefs(ast.left, outSet);
            _collectConditionRefs(ast.right, outSet);
            return;
        }

        if (ast.type === 'not') {
            _collectConditionRefs(ast.expr, outSet);
            return;
        }

        if ((ast.type === 'all_of' || ast.type === 'any_of') && Array.isArray(ast.identifiers)) {
            ast.identifiers.forEach(id => outSet.add(String(id).toLowerCase()));
        }
    }

    function _validateSigmaRule(rule) {
        const missing = [];

        if (!rule || typeof rule !== 'object') {
            missing.push('rule');
            return missing;
        }

        if (!rule.title || String(rule.title).trim() === '') {
            missing.push('title');
        }

        const ls = rule.logsource;
        if (!ls || typeof ls !== 'object' || Object.keys(ls).length === 0) {
            missing.push('logsource');
        }

        const det = rule.detection;
        if (!det || typeof det !== 'object') {
            missing.push('detection');
            return missing;
        }

        if (!det.conditionStr || String(det.conditionStr).trim() === '') {
            missing.push('detection.condition');
        }

        if (!det.conditionAst || typeof det.conditionAst !== 'object') {
            missing.push('detection.conditionAst');
        }

        const identifiers = det.identifiers || {};
        if (Object.keys(identifiers).length === 0) {
            missing.push('detection.identifiers');
            return missing;
        }

        const hasSignal = Object.values(identifiers).some(idNode => _identifierHasSignal(idNode));
        if (!hasSignal) {
            missing.push('detection.identifiers(non-empty)');
        }

        if (det.conditionAst) {
            const refs = new Set();
            _collectConditionRefs(det.conditionAst, refs);
            const knownRefs = new Set(Object.keys(identifiers).map(k => k.toLowerCase()));
            const unknownRefs = [...refs].filter(r => !knownRefs.has(r));
            if (unknownRefs.length > 0) {
                missing.push(`detection.condition references unknown identifier(s): ${unknownRefs.join(', ')}`);
            }
        }

        return missing;
    }

    function _parseSigmaOrNormalize(input) {
        try {
            const rule = SigmaParser.parseSigmaRule(input);
            const missing = _validateSigmaRule(rule);
            if (missing.length > 0) {
                throw new Error(`Sigma rule is missing required fields: ${missing.join(', ')}`);
            }
            return rule;
        } catch (err) {
            const detected = _detectInputFormat(input);
            if (detected === 'sigma') throw err;
            const sigmaText = _toSigmaFromQuery(input, detected === 'query' ? 'splunk' : detected);
            return SigmaParser.parseSigmaRule(sigmaText);
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Operator definitions
    // Each operator has:
    //   id, name, category, icon, description, inputFormat, outputFormat,
    //   options (array of config items), run(input, options) → string
    // ────────────────────────────────────────────────────────────────────
    const operators = [

        // ── Parse / Inspect ──────────────────────────────────────────────
        {
            id: 'sigma-inspect',
            name: 'Inspect Rule',
            category: 'parse',
            icon: 'bi-search',
            description: 'Parse the selected source rule and display structure and metadata.',
            fromFormat: 'sigma',
            toFormat: 'json',
            options: [],
            run(input /*, opts */) {
                const rule = _parseSigmaOrNormalize(input);
                const summary = SigmaParser.summarize(rule);
                return JSON.stringify({
                    metadata: {
                        title: rule.title,
                        id: rule.id,
                        author: rule.author,
                        status: rule.status,
                        level: rule.level,
                        logsource: rule.logsource,
                        tags: rule.tags,
                    },
                    detection: {
                        condition: rule.detection.conditionStr,
                        identifiers: Object.fromEntries(
                            Object.entries(rule.detection.identifiers).map(([k, v]) => [k, v])
                        ),
                        timeframe: rule.detection.timeframe,
                    },
                    fields: rule.fields,
                    falsepositives: rule.falsepositives,
                }, null, 2);
            }
        },

        // ── Sigma → Splunk SPL ───────────────────────────────────────────
        {
            id: 'sigma-to-splunk',
            name: 'Splunk SPL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#ff6b35',
            description: 'Convert the selected source rule to a Splunk SPL search query.',
            fromFormat: 'sigma',
            toFormat: 'splunk',
            options: [
                {
                    id: 'addComments',
                    label: 'Include rule metadata comments',
                    type: 'checkbox',
                    default: true,
                }
            ],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new SplunkBackend({
                    addComments: opts.addComments !== false,
                });
                return backend.convert(rule);
            }
        },

        // ── Sigma → Elastic Lucene ───────────────────────────────────────
        {
            id: 'sigma-to-elastic',
            name: 'Elastic Lucene',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#00bfb3',
            description: 'Convert the selected source rule to an Elasticsearch Lucene query string.',
            fromFormat: 'sigma',
            toFormat: 'elastic',
            options: [
                {
                    id: 'addComments',
                    label: 'Include rule metadata comments',
                    type: 'checkbox',
                    default: true,
                }
            ],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new ElasticLuceneBackend({
                    addComments: opts.addComments !== false,
                });
                return backend.convert(rule);
            }
        },

        // ── Sigma → Microsoft Sentinel KQL ──────────────────────────────
        {
            id: 'sigma-to-kql-sentinel',
            name: 'Sentinel KQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#0078d4',
            description: 'Convert the selected source rule to Microsoft Sentinel KQL (Log Analytics / SecurityEvent tables).',
            fromFormat: 'sigma',
            toFormat: 'kql',
            options: [
                {
                    id: 'platform',
                    label: 'Platform',
                    type: 'select',
                    options: [
                        { value: 'sentinel',  label: 'Microsoft Sentinel' },
                        { value: 'defender',  label: 'Defender for Endpoint (MDE)' },
                    ],
                    default: 'sentinel',
                },
                {
                    id: 'addComments',
                    label: 'Include rule metadata comments',
                    type: 'checkbox',
                    default: true,
                }
            ],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new KqlBackend({
                    platform: opts.platform || 'sentinel',
                    addComments: opts.addComments !== false,
                });
                return backend.convert(rule);
            }
        },

        // ── Sigma → Carbon Black ─────────────────────────────────────────
        {
            id: 'sigma-to-cb',
            name: 'Carbon Black',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#e8534a',
            description: 'Convert the selected source rule to Carbon Black EDR / CB Cloud Lucene-style query.',
            fromFormat: 'sigma',
            toFormat: 'cb',
            options: [
                {
                    id: 'variant',
                    label: 'CB Variant',
                    type: 'select',
                    options: [
                        { value: 'eedr',  label: 'CB Enterprise EDR (on-premise)' },
                        { value: 'cloud', label: 'CB Cloud / ThreatHunter' },
                    ],
                    default: 'eedr',
                },
                {
                    id: 'addComments',
                    label: 'Include rule metadata comments',
                    type: 'checkbox',
                    default: true,
                },
                {
                    id: 'allowLeadingWildcards',
                    label: 'Allow leading wildcards (legacy)',
                    type: 'checkbox',
                    default: false,
                }
            ],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new CarbonBlackBackend({
                    variant: opts.variant || 'eedr',
                    addComments: opts.addComments !== false,
                    allowLeadingWildcards: opts.allowLeadingWildcards === true,
                });
                return backend.convert(rule);
            }
        },

        // ── Sigma → Velociraptor VQL ─────────────────────────────────────
        {
            id: 'sigma-to-vql',
            name: 'Velociraptor VQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#7c4dff',
            description: 'Convert the selected source rule to Velociraptor VQL for endpoint forensics and incident response.',
            fromFormat: 'sigma',
            toFormat: 'vql',
            options: [
                {
                    id: 'limit',
                    label: 'LIMIT rows',
                    type: 'number',
                    default: 1000,
                    min: 1,
                    max: 100000,
                },
                {
                    id: 'addComments',
                    label: 'Include rule metadata comments',
                    type: 'checkbox',
                    default: true,
                }
            ],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new VqlBackend({
                    limit: parseInt(opts.limit) || 1000,
                    addComments: opts.addComments !== false,
                });
                return backend.convert(rule);
            }
        },

        {
            id: 'sigma-to-aql',
            name: 'QRadar AQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#5c7cfa',
            description: 'Convert the selected source rule to IBM QRadar AQL.',
            fromFormat: 'sigma',
            toFormat: 'aql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new AqlBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-nwql',
            name: 'RSA NetWitness Query',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#1d4ed8',
            description: 'Convert the selected source rule to RSA NetWitness query syntax.',
            fromFormat: 'sigma',
            toFormat: 'nwql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new NetWitnessBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-ppl',
            name: 'OpenSearch PPL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#12b886',
            description: 'Convert the selected source rule to OpenSearch PPL.',
            fromFormat: 'sigma',
            toFormat: 'ppl',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new PplBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-xql',
            name: 'Palo Alto XQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#f59f00',
            description: 'Convert the selected source rule to Cortex XDR XQL.',
            fromFormat: 'sigma',
            toFormat: 'xql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new XqlBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-oql',
            name: 'Securonix OQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#e64980',
            description: 'Convert the selected source rule to Securonix OQL.',
            fromFormat: 'sigma',
            toFormat: 'oql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new OqlBackend({ flavor: 'securonix', addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-oql-securityonion',
            name: 'Security Onion OQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#ff922b',
            description: 'Convert the selected source rule to Security Onion OQL.',
            fromFormat: 'sigma',
            toFormat: 'oql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new OqlBackend({ flavor: 'securityonion', addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-arcsight',
            name: 'ArcSight Query',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#20c997',
            description: 'Convert the selected source rule to ArcSight query syntax.',
            fromFormat: 'sigma',
            toFormat: 'arcsight',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new ArcSightBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-ddql',
            name: 'Datadog Log Query',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#7048e8',
            description: 'Convert the selected source rule to Datadog log query syntax.',
            fromFormat: 'sigma',
            toFormat: 'ddql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new DdqlBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-s1ql',
            name: 'SentinelOne Deep Visibility',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#fa5252',
            description: 'Convert the selected source rule to SentinelOne Deep Visibility query syntax.',
            fromFormat: 'sigma',
            toFormat: 's1ql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new S1qlBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-eql',
            name: 'Elastic EQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#15aabf',
            description: 'Convert the selected source rule to Elastic EQL.',
            fromFormat: 'sigma',
            toFormat: 'eql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new EqlBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-yaral',
            name: 'Chronicle YARA-L',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#845ef7',
            description: 'Convert the selected source rule to Chronicle YARA-L.',
            fromFormat: 'sigma',
            toFormat: 'yaral',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new YaraLBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-graylog',
            name: 'Graylog Query String',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#74c0fc',
            description: 'Convert the selected source rule to Graylog query string syntax.',
            fromFormat: 'sigma',
            toFormat: 'graylog',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new GraylogBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-sumoql',
            name: 'Sumo Logic',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#38d9a9',
            description: 'Convert the selected source rule to Sumo Logic query syntax.',
            fromFormat: 'sigma',
            toFormat: 'sumoql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new SumoBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-logscale',
            name: 'Falcon LogScale',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#ffe066',
            description: 'Convert the selected source rule to Falcon LogScale query syntax.',
            fromFormat: 'sigma',
            toFormat: 'logscale',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new LogScaleBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-logql',
            name: 'Grafana Loki LogQL',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#66d9e8',
            description: 'Convert the selected source rule to Grafana Loki LogQL.',
            fromFormat: 'sigma',
            toFormat: 'logql',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new LogqlBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-cwli',
            name: 'CloudWatch Logs Insights',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#74b816',
            description: 'Convert the selected source rule to AWS CloudWatch Logs Insights syntax.',
            fromFormat: 'sigma',
            toFormat: 'cwli',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new CloudWatchBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-udm',
            name: 'Chronicle UDM Search',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#3b82f6',
            description: 'Convert the selected source rule to Google Chronicle UDM search syntax.',
            fromFormat: 'sigma',
            toFormat: 'udm',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new ChronicleUdmBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        {
            id: 'sigma-to-sysmonxml',
            name: 'Sysmon XML',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#64748b',
            description: 'Convert the selected source rule to Sysmon XML EventFiltering syntax.',
            fromFormat: 'sigma',
            toFormat: 'sysmonxml',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new SysmonXmlBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },

        {
            id: 'splunk-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#ff6b35',
            description: 'Normalize a Splunk SPL query into a Sigma YAML starter rule.',
            fromFormat: 'splunk',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'splunk');
            }
        },
        {
            id: 'elastic-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#00bfb3',
            description: 'Normalize an Elastic Lucene query into a Sigma YAML starter rule.',
            fromFormat: 'elastic',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'elastic');
            }
        },
        {
            id: 'kql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#0078d4',
            description: 'Normalize a KQL query into a Sigma YAML starter rule.',
            fromFormat: 'kql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'kql');
            }
        },
        {
            id: 'cb-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#e8534a',
            description: 'Normalize a Carbon Black query into a Sigma YAML starter rule.',
            fromFormat: 'cb',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'cb');
            }
        },
        {
            id: 'vql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#7c4dff',
            description: 'Normalize a Velociraptor VQL query into a Sigma YAML starter rule.',
            fromFormat: 'vql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'vql');
            }
        },
        {
            id: 'aql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#5c7cfa',
            description: 'Normalize a QRadar AQL query into a Sigma YAML starter rule.',
            fromFormat: 'aql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'aql');
            }
        },
        {
            id: 'nwql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#1d4ed8',
            description: 'Normalize an RSA NetWitness query into a Sigma YAML starter rule.',
            fromFormat: 'nwql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'nwql');
            }
        },
        {
            id: 'ppl-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#12b886',
            description: 'Normalize an OpenSearch PPL query into a Sigma YAML starter rule.',
            fromFormat: 'ppl',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'ppl');
            }
        },
        {
            id: 'xql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#f59f00',
            description: 'Normalize a Cortex XQL query into a Sigma YAML starter rule.',
            fromFormat: 'xql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'xql');
            }
        },
        {
            id: 'oql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#e64980',
            description: 'Normalize an OQL query into a Sigma YAML starter rule.',
            fromFormat: 'oql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'oql');
            }
        },
        {
            id: 'arcsight-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#20c997',
            description: 'Normalize an ArcSight query into a Sigma YAML starter rule.',
            fromFormat: 'arcsight',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'arcsight');
            }
        },
        {
            id: 'ddql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#7048e8',
            description: 'Normalize a Datadog query into a Sigma YAML starter rule.',
            fromFormat: 'ddql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'ddql');
            }
        },
        {
            id: 's1ql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#fa5252',
            description: 'Normalize a SentinelOne Deep Visibility query into a Sigma YAML starter rule.',
            fromFormat: 's1ql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 's1ql');
            }
        },
        {
            id: 'eql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#15aabf',
            description: 'Normalize an Elastic EQL query into a Sigma YAML starter rule.',
            fromFormat: 'eql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'eql');
            }
        },
        {
            id: 'yaral-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#845ef7',
            description: 'Normalize a YARA-L rule into a Sigma YAML starter rule.',
            fromFormat: 'yaral',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'yaral');
            }
        },
        {
            id: 'graylog-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#74c0fc',
            description: 'Normalize a Graylog query string into a Sigma YAML starter rule.',
            fromFormat: 'graylog',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'graylog');
            }
        },
        {
            id: 'sumoql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#38d9a9',
            description: 'Normalize a Sumo Logic query into a Sigma YAML starter rule.',
            fromFormat: 'sumoql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'sumoql');
            }
        },
        {
            id: 'logscale-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#ffe066',
            description: 'Normalize a Falcon LogScale query into a Sigma YAML starter rule.',
            fromFormat: 'logscale',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'logscale');
            }
        },
        {
            id: 'logql-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#66d9e8',
            description: 'Normalize a Loki LogQL query into a Sigma YAML starter rule.',
            fromFormat: 'logql',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'logql');
            }
        },
        {
            id: 'cwli-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#74b816',
            description: 'Normalize a CloudWatch Logs Insights query into a Sigma YAML starter rule.',
            fromFormat: 'cwli',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'cwli');
            }
        },
        {
            id: 'udm-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#3b82f6',
            description: 'Normalize a Chronicle UDM search query into a Sigma YAML starter rule.',
            fromFormat: 'udm',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'udm');
            }
        },
        {
            id: 'sysmonxml-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#64748b',
            description: 'Normalize a Sysmon XML EventFiltering snippet into a Sigma YAML starter rule.',
            fromFormat: 'sysmonxml',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'sysmonxml');
            }
        },
        // ── Sigma → Rapid7 InsightIDR LEQL ──────────────────────────
        {
            id: 'sigma-to-rapid7',
            name: 'Rapid7 InsightIDR',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#e67e22',
            description: 'Convert the selected source rule to Rapid7 InsightIDR LEQL.',
            fromFormat: 'sigma',
            toFormat: 'rapid7',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new Rapid7Backend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        // ── Sigma → Anomali ThreatStream ────────────────────────────
        {
            id: 'sigma-to-anomali',
            name: 'Anomali ThreatStream',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#9b59b6',
            description: 'Convert the selected source rule to Anomali ThreatStream query syntax.',
            fromFormat: 'sigma',
            toFormat: 'anomali',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new AnomaliBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        // ── Sigma → Logger (Sumo-style) ────────────────────────────
        {
            id: 'sigma-to-logger',
            name: 'Logger (Sumo-style)',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#16a085',
            description: 'Convert the selected source rule to Logger Sumo Logic-style query syntax.',
            fromFormat: 'sigma',
            toFormat: 'logger',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new LoggerBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        // ── Sigma → ElastAlert Lucene ──────────────────────────────
        {
            id: 'sigma-to-elastalert',
            name: 'ElastAlert Lucene',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#2980b9',
            description: 'Convert the selected source rule to ElastAlert Lucene query syntax.',
            fromFormat: 'sigma',
            toFormat: 'elastalert',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new ElastAlertBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        // ── Sigma → FortiSIEM ───────────────────────────────────────
        {
            id: 'sigma-to-fortisiem',
            name: 'FortiSIEM',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#d35400',
            description: 'Convert the selected source rule to FortiSIEM query syntax.',
            fromFormat: 'sigma',
            toFormat: 'fortisiem',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new FortiSIEMBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        // ── Sigma → Tanium ──────────────────────────────────────────
        {
            id: 'sigma-to-tanium',
            name: 'Tanium',
            category: 'convert',
            icon: 'bi-box-arrow-right',
            color: '#c0392b',
            description: 'Convert the selected source rule to Tanium query language.',
            fromFormat: 'sigma',
            toFormat: 'tanium',
            options: [],
            run(input, opts = {}) {
                const rule = _parseSigmaOrNormalize(input);
                const backend = new TaniumBackend({ addComments: opts.addComments !== false });
                return backend.convert(rule);
            }
        },
        // ── Rapid7 → Sigma ──────────────────────────────────────────
        {
            id: 'rapid7-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#e67e22',
            description: 'Normalize a Rapid7 InsightIDR LEQL query into a Sigma YAML starter rule.',
            fromFormat: 'rapid7',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'rapid7');
            }
        },
        // ── Anomali → Sigma ─────────────────────────────────────────
        {
            id: 'anomali-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#9b59b6',
            description: 'Normalize an Anomali ThreatStream query into a Sigma YAML starter rule.',
            fromFormat: 'anomali',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'anomali');
            }
        },
        // ── Logger → Sigma ──────────────────────────────────────────
        {
            id: 'logger-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#16a085',
            description: 'Normalize a Logger Sumo-style query into a Sigma YAML starter rule.',
            fromFormat: 'logger',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'logger');
            }
        },
        // ── ElastAlert → Sigma ──────────────────────────────────────
        {
            id: 'elastalert-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#2980b9',
            description: 'Normalize an ElastAlert Lucene query into a Sigma YAML starter rule.',
            fromFormat: 'elastalert',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'elastalert');
            }
        },
        // ── FortiSIEM → Sigma ───────────────────────────────────────
        {
            id: 'fortisiem-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#d35400',
            description: 'Normalize a FortiSIEM query into a Sigma YAML starter rule.',
            fromFormat: 'fortisiem',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'fortisiem');
            }
        },
        // ── Tanium → Sigma ──────────────────────────────────────────
        {
            id: 'tanium-to-sigma',
            name: 'To Sigma',
            category: 'convert',
            icon: 'bi-arrow-return-left',
            color: '#c0392b',
            description: 'Normalize a Tanium query into a Sigma YAML starter rule.',
            fromFormat: 'tanium',
            toFormat: 'sigma',
            options: [],
            run(input) {
                return _toSigmaFromQuery(input, 'tanium');
            }
        },
    ];

    // ── Category metadata ────────────────────────────────────────────────
    const categories = [
        { id: 'parse',   label: 'Parse & Inspect',  icon: 'bi-search',       color: '#868e96' },
        { id: 'convert', label: 'Convert to SIEM',  icon: 'bi-arrow-left-right', color: '#4dabf7' },
    ];

    const inputFormatLabels = {
        sigma: 'Sigma YAML',
        splunk: 'Splunk SPL',
        elastic: 'Elastic Lucene',
        kql: 'KQL',
        cb: 'Carbon Black Query',
        vql: 'Velociraptor VQL',
        aql: 'QRadar AQL',
        nwql: 'RSA NetWitness Query',
        ppl: 'OpenSearch PPL',
        xql: 'Palo Alto XQL',
        oql: 'Securonix OQL',
        arcsight: 'ArcSight Query',
        ddql: 'Datadog Log Query',
        s1ql: 'SentinelOne Deep Visibility',
        eql: 'Elastic EQL',
        yaral: 'Chronicle YARA-L',
        graylog: 'Graylog Query String',
        sumoql: 'Sumo Logic',
        logscale: 'Falcon LogScale',
        logql: 'Grafana Loki LogQL',
        cwli: 'CloudWatch Logs Insights',
        udm: 'Chronicle UDM Search',
        sysmonxml: 'Sysmon XML',
        json: 'JSON',
        rapid7: 'Rapid7 InsightIDR LEQL',
        anomali: 'Anomali ThreatStream',
        logger: 'Logger (Sumo-style)',
        elastalert: 'ElastAlert Lucene',
        fortisiem: 'FortiSIEM Query',
        tanium: 'Tanium Query',
    };

    // ── Public API ───────────────────────────────────────────────────────
    function getAll()       { return operators; }
    function getById(id)    { return operators.find(o => o.id === id); }
    function getByCategory(cat) { return operators.filter(o => o.category === cat); }
    function getCategories()    { return categories; }
    function getInputFormats() {
        return Array.from(new Set(operators.map(o => o.fromFormat).filter(Boolean)));
    }
    function getInputFormatLabel(format) {
        return inputFormatLabels[format] || String(format || '').toUpperCase();
    }

    return { getAll, getById, getByCategory, getCategories, getInputFormats, getInputFormatLabel };
})();
