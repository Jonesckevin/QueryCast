/**
 * sigma-parser.js
 * Core Sigma YAML rule parser and condition expression evaluator.
 * Parses Sigma v2.0+ rules into an internal AST for backend conversion.
 */
'use strict';

const SigmaParser = (() => {

    // ────────────────────────────────────────────────────────────
    // Condition string tokenizer
    // ────────────────────────────────────────────────────────────
    function tokenize(conditionStr) {
        const tokens = [];
        const str = conditionStr.trim();
        let i = 0;

        while (i < str.length) {
            const ch = str[i];
            if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') { i++; continue; }
            if (ch === '(') { tokens.push({ type: 'lparen', value: '(' }); i++; continue; }
            if (ch === ')') { tokens.push({ type: 'rparen', value: ')' }); i++; continue; }

            if (/[a-zA-Z0-9_*]/.test(ch)) {
                let word = '';
                while (i < str.length && /[a-zA-Z0-9_*]/.test(str[i])) {
                    word += str[i++];
                }
                const lower = word.toLowerCase();
                if (lower === 'and')  tokens.push({ type: 'and',  value: lower });
                else if (lower === 'or')   tokens.push({ type: 'or',   value: lower });
                else if (lower === 'not')  tokens.push({ type: 'not',  value: lower });
                else if (lower === 'of')   tokens.push({ type: 'of',   value: lower });
                else if (lower === 'all')  tokens.push({ type: 'all',  value: lower });
                else if (/^\d+$/.test(word)) tokens.push({ type: 'number', value: parseInt(word) });
                else tokens.push({ type: 'identifier', value: lower }); // lowercase for matching
                continue;
            }
            i++;
        }
        return tokens;
    }

    // ────────────────────────────────────────────────────────────
    // Condition expression parser → AST
    // Grammar:
    //   expr   := term ( 'or' term )*
    //   term   := factor ( 'and' factor )*
    //   factor := 'not' factor | atom
    //   atom   := '(' expr ')' | quantifier | identifier
    //   quantifier := ( NUMBER | 'all' ) 'of' PATTERN
    // ────────────────────────────────────────────────────────────
    function parseCondition(conditionStr, detectionKeys) {
        const tokens = tokenize(conditionStr);
        let pos = 0;

        function peek() { return pos < tokens.length ? tokens[pos] : null; }
        function consume() { return tokens[pos++]; }
        function expect(type) {
            const t = peek();
            if (!t || t.type !== type) throw new Error(`Expected token "${type}" but got "${t ? t.type : 'EOF'}" in condition: ${conditionStr}`);
            return consume();
        }

        function parseExpr() {
            let left = parseTerm();
            while (peek()?.type === 'or') {
                consume();
                left = { type: 'or', left, right: parseTerm() };
            }
            return left;
        }

        function parseTerm() {
            let left = parseFactor();
            while (peek()?.type === 'and') {
                consume();
                left = { type: 'and', left, right: parseFactor() };
            }
            return left;
        }

        function parseFactor() {
            if (peek()?.type === 'not') {
                consume();
                return { type: 'not', expr: parseFactor() };
            }
            return parseAtom();
        }

        function parseAtom() {
            const t = peek();
            if (!t) throw new Error('Unexpected end of condition: ' + conditionStr);

            // Grouped expression
            if (t.type === 'lparen') {
                consume();
                const expr = parseExpr();
                expect('rparen');
                return expr;
            }

            // Quantifier: "1 of selection*"  or  "all of selection*"
            if (t.type === 'number' || t.type === 'all') {
                const quantifier = consume().value;
                expect('of');
                const pattern = consume().value;
                const matchingIds = detectionKeys.filter(k => matchesWildcard(k.toLowerCase(), pattern.toLowerCase()));

                if (matchingIds.length === 0) {
                    console.warn(`Quantifier "${quantifier} of ${pattern}" matched no identifiers. Keys: ${detectionKeys.join(', ')}`);
                }

                return quantifier === 'all'
                    ? { type: 'all_of', identifiers: matchingIds }
                    : { type: 'any_of', count: quantifier, identifiers: matchingIds };
            }

            // Simple identifier reference
            if (t.type === 'identifier') {
                const name = consume().value;
                return { type: 'ref', name };
            }

            throw new Error(`Unexpected token "${t.type}" (${t.value}) in condition: ${conditionStr}`);
        }

        return parseExpr();
    }

    // ────────────────────────────────────────────────────────────
    // Glob/wildcard matching for quantifier patterns like "selection*"
    // ────────────────────────────────────────────────────────────
    function matchesWildcard(str, pattern) {
        const regexStr = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
        return new RegExp(regexStr).test(str);
    }

    // ────────────────────────────────────────────────────────────
    // Parse a field key like "Image|endswith|all" into parts
    // ────────────────────────────────────────────────────────────
    function parseFieldKey(key) {
        const parts = key.split('|');
        return {
            field: parts[0],
            modifiers: parts.slice(1).filter(m => m.trim() !== '')
        };
    }

    // ────────────────────────────────────────────────────────────
    // Parse one detection identifier block
    // Can be:
    //   - Object: { Image|endswith: [...], CommandLine|contains: '...' }
    //   - List of strings (keyword search)
    //   - List of objects (OR between objects)
    //   - A scalar string or number (single keyword)
    // ────────────────────────────────────────────────────────────
    function parseDetectionIdentifier(content) {
        if (content === null || content === undefined) return null;

        if (Array.isArray(content)) {
            if (content.length === 0) return null;

            const firstItem = content[0];
            if (typeof firstItem === 'string' || typeof firstItem === 'number') {
                // Keyword list – searched across all fields (full-text)
                return { type: 'keywords', values: content.map(String) };
            }
            if (typeof firstItem === 'object') {
                // List of objects → OR logic between them
                return {
                    type: 'or_conditions',
                    conditions: content.map(item => parseFieldValueObject(item))
                };
            }
        }

        if (typeof content === 'object' && content !== null && !Array.isArray(content)) {
            return parseFieldValueObject(content);
        }

        if (typeof content === 'string' || typeof content === 'number') {
            return { type: 'keywords', values: [String(content)] };
        }

        return null;
    }

    // ────────────────────────────────────────────────────────────
    // Parse a field-value object (all fields AND'd together)
    // ────────────────────────────────────────────────────────────
    function parseFieldValueObject(obj) {
        const conditions = [];

        for (const [key, rawValue] of Object.entries(obj)) {
            const { field, modifiers } = parseFieldKey(key);

            const useAll = modifiers.includes('all');
            const filterMods = modifiers.filter(m => m !== 'all');

            const values = rawValue === null
                ? [null]
                : Array.isArray(rawValue)
                    ? rawValue
                    : [rawValue];

            conditions.push({
                type: 'field_condition',
                field,
                modifiers: filterMods,
                useAll,
                values: values.map(v => (v === null || v === undefined) ? null : String(v))
            });
        }

        if (conditions.length === 0) return null;
        if (conditions.length === 1) return conditions[0];
        return { type: 'and_conditions', conditions };
    }

    // ────────────────────────────────────────────────────────────
    // Main entry point: parse a Sigma YAML string
    // ────────────────────────────────────────────────────────────
    function parseSigmaRule(yamlText) {
        if (typeof jsyaml === 'undefined') {
            throw new Error('js-yaml library not loaded. Please include it before sigma-parser.js.');
        }

        let raw;
        try {
            raw = jsyaml.load(yamlText);
        } catch (e) {
            throw new Error('YAML parse error: ' + e.message);
        }

        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
            throw new Error('Invalid Sigma rule: root element must be a YAML object');
        }

        const detection = raw.detection || {};
        const conditionRaw = detection.condition;

        if (conditionRaw === undefined || conditionRaw === null) {
            throw new Error('Missing required field: detection.condition');
        }

        // Normalise condition to string (may be a list in some edge-cases)
        const conditionStr = Array.isArray(conditionRaw)
            ? conditionRaw.join(' | ')
            : String(conditionRaw);

        // Parse each identifier (everything except reserved keys)
        const RESERVED = new Set(['condition', 'timeframe']);
        const identifiers = {};

        for (const [key, value] of Object.entries(detection)) {
            if (RESERVED.has(key)) continue;
            identifiers[key] = parseDetectionIdentifier(value);
        }

        const detectionKeys = Object.keys(identifiers);
        let conditionAst;
        try {
            conditionAst = parseCondition(conditionStr, detectionKeys);
        } catch (e) {
            throw new Error('Condition parse error: ' + e.message);
        }

        return {
            raw,
            // Metadata
            title: raw.title || '',
            id: raw.id || '',
            description: raw.description || '',
            author: Array.isArray(raw.author) ? raw.author.join(', ') : (raw.author || ''),
            status: raw.status || 'experimental',
            level: raw.level || '',
            tags: Array.isArray(raw.tags) ? raw.tags : [],
            references: Array.isArray(raw.references) ? raw.references : [],
            // Logsource
            logsource: raw.logsource || {},
            // Detection
            detection: {
                identifiers,
                conditionStr,
                conditionAst,
                timeframe: detection.timeframe || null
            },
            // Additional fields
            fields: Array.isArray(raw.fields) ? raw.fields : [],
            falsepositives: Array.isArray(raw.falsepositives) ? raw.falsepositives : []
        };
    }

    // ────────────────────────────────────────────────────────────
    // Describe the rule summary (for UI display)
    // ────────────────────────────────────────────────────────────
    function summarize(sigmaRule) {
        const ls = sigmaRule.logsource;
        const lsStr = [ls.product, ls.category || ls.service].filter(Boolean).join('/');
        return {
            title: sigmaRule.title || '(untitled)',
            level: sigmaRule.level,
            status: sigmaRule.status,
            logsource: lsStr,
            identifierCount: Object.keys(sigmaRule.detection.identifiers).length,
            condition: sigmaRule.detection.conditionStr
        };
    }

    return {
        parseSigmaRule,
        parseCondition,
        parseFieldKey,
        parseDetectionIdentifier,
        matchesWildcard,
        summarize
    };
})();
