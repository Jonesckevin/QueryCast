/**
 * query-parser.js
 * Generic SIEM query tokenizer and AST builder.
 *
 * Parses common SIEM query patterns into an intermediate representation
 * that backends can convert back to Sigma or other formats.
 *
 * Supports:
 *  - Field:value syntax with wildcards
 *  - AND / OR / NOT operators
 *  - Parenthesized expressions
 *  - Escaped characters
 *  - Quoted strings
 */
'use strict';

const QueryParser = (() => {

    // ── Token types ─────────────────────────────────────────────────────
    const TOKEN_TYPES = {
        FIELD:    'FIELD',
        OPERATOR: 'OPERATOR',
        VALUE:    'VALUE',
        LOGICAL:  'LOGICAL',   // AND, OR, NOT
        PAREN_OPEN: 'PAREN_OPEN',
        PAREN_CLOSE: 'PAREN_CLOSE',
        PIPE:     'PIPE',       // |
        EOF:      'EOF',
    };

    // ── Tokenizer ───────────────────────────────────────────────────────
    function tokenize(query) {
        if (!query) return [];
        const tokens = [];
        let i = 0;

        function peek(offset = 0) { return query[i + offset]; }
        function advance() { return query[i++]; }
        function isWhitespace(ch) { return /\s/.test(ch); }
        function isIdentStart(ch) { return /[a-z_]/i.test(ch); }
        function isIdentChar(ch) { return /[a-z0-9_.-]/i.test(ch); }

        while (i < query.length) {
            const ch = peek();

            // Whitespace
            if (isWhitespace(ch)) { advance(); continue; }

            // Parentheses
            if (ch === '(') { tokens.push({ type: TOKEN_TYPES.PAREN_OPEN, value: '(', pos: i }); advance(); continue; }
            if (ch === ')') { tokens.push({ type: TOKEN_TYPES.PAREN_CLOSE, value: ')', pos: i }); advance(); continue; }

            // Pipe
            if (ch === '|') { tokens.push({ type: TOKEN_TYPES.PIPE, value: '|', pos: i }); advance(); continue; }

            // Quoted string
            if (ch === '"' || ch === "'") {
                const quote = ch;
                advance(); // skip opening quote
                let value = '';
                while (i < query.length && peek() !== quote) {
                    if (peek() === '\\') { 
                        advance(); 
                        if (i < query.length) {
                            const nextChar = peek();
                            if (nextChar === 'n') { value += '\n'; advance(); }
                            else if (nextChar === 't') { value += '\t'; advance(); }
                            else if (nextChar === '\\') { value += '\\'; advance(); }
                            else if (nextChar === quote) { value += quote; advance(); }
                            else {
                                value += '\\' + nextChar;
                                advance();
                            }
                        }
                    }
                    else { value += advance(); }
                }
                advance(); // skip closing quote
                tokens.push({ type: TOKEN_TYPES.VALUE, value, pos: i });
                continue;
            }

            // Identifier (field, operator keyword, or value)
            if (isIdentStart(ch)) {
                let ident = '';
                while (i < query.length && isIdentChar(peek())) { ident += advance(); }

                const upper = ident.toUpperCase();
                if (upper === 'AND' || upper === 'OR' || upper === 'NOT') {
                    tokens.push({ type: TOKEN_TYPES.LOGICAL, value: upper, pos: i - ident.length });
                } else if (peek() === ':' || peek() === '|' || peek() === '-') {
                    // Likely a field name (followed by : or | or -)
                    tokens.push({ type: TOKEN_TYPES.FIELD, value: ident, pos: i - ident.length });
                } else {
                    // Standalone keyword or value
                    tokens.push({ type: TOKEN_TYPES.VALUE, value: ident, pos: i - ident.length });
                }
                continue;
            }

            // Operators and special chars
            if (ch === ':') { tokens.push({ type: TOKEN_TYPES.OPERATOR, value: ':', pos: i }); advance(); continue; }
            if (ch === '-' && (tokens.length === 0 || tokens[tokens.length - 1].type === TOKEN_TYPES.LOGICAL ||
                               tokens[tokens.length - 1].type === TOKEN_TYPES.PAREN_OPEN ||
                               tokens[tokens.length - 1].type === TOKEN_TYPES.OPERATOR)) {
                // Negation prefix
                tokens.push({ type: TOKEN_TYPES.LOGICAL, value: 'NOT', pos: i });
                advance();
                continue;
            }
            if (ch === '\\') {
                // Escaped character in value - only unescape known sequences
                advance(); // skip backslash
                let value = '';
                if (i < query.length) {
                    const nextChar = peek();
                    // Only unescape recognized sequences: \n, \t, \\, \"  others remain literal
                    if (nextChar === 'n') { value = '\n'; advance(); }
                    else if (nextChar === 't') { value = '\t'; advance(); }
                    else if (nextChar === '\\') { value = '\\'; advance(); }
                    else if (nextChar === '"') { value = '"'; advance(); }
                    else if (nextChar === "'") { value = "'"; advance(); }
                    else {
                        // Unknown escape - keep the backslash and the character
                        value = '\\' + advance();
                    }
                }
                // Continue reading the value with the escaped char
                while (i < query.length) {
                    const c = peek();
                    if (isWhitespace(c) || c === '(' || c === ')' || c === '|') break;
                    if (c === ':' || c === '-') break;
                    if (c === '\\') { 
                        advance(); 
                        const nextChar = peek();
                        if (nextChar === 'n') { value += '\n'; advance(); }
                        else if (nextChar === 't') { value += '\t'; advance(); }
                        else if (nextChar === '\\') { value += '\\'; advance(); }
                        else if (nextChar === '"') { value += '"'; advance(); }
                        else if (nextChar === "'") { value += "'"; advance(); }
                        else {
                            value += '\\' + (peek() || '');
                            if (i < query.length) advance();
                        }
                    }
                    else { value += advance(); }
                }
                tokens.push({ type: TOKEN_TYPES.VALUE, value, pos: i - value.length });
                continue;
            }

            // Multi-char value (for wildcards, hyphens, etc.)
            let value = '';
            while (i < query.length) {
                const c = peek();
                if (isWhitespace(c) || c === '(' || c === ')' || c === '|') break;
                if (c === ':' || c === '-') break;
                if (isIdentStart(c) && value && !/[-*:]/.test(value[value.length - 1])) break;
                if (c === '\\') { 
                    advance(); 
                    const nextChar = peek();
                    if (nextChar === 'n') { value += '\n'; advance(); }
                    else if (nextChar === 't') { value += '\t'; advance(); }
                    else if (nextChar === '\\') { value += '\\'; advance(); }
                    else if (nextChar === '"') { value += '"'; advance(); }
                    else if (nextChar === "'") { value += "'"; advance(); }
                    else {
                        value += '\\' + (peek() || '');
                        if (i < query.length) advance();
                    }
                }
                else { value += advance(); }
            }
            if (value) { tokens.push({ type: TOKEN_TYPES.VALUE, value, pos: i - value.length }); }
        }

        tokens.push({ type: TOKEN_TYPES.EOF, value: '', pos: i });
        return tokens;
    }

    // ── AST Nodes ───────────────────────────────────────────────────────
    class ASTNode {}

    class Comparison extends ASTNode {
        constructor(field, operator, value) {
            super();
            this.type = 'Comparison';
            this.field = field;
            this.operator = operator;  // ':', '*:', ':*', '*:*', 'regex', 'contains', etc.
            this.value = value;
        }
    }

    class BinaryOp extends ASTNode {
        constructor(op, left, right) {
            super();
            this.type = 'BinaryOp';
            this.op = op;  // 'AND', 'OR'
            this.left = left;
            this.right = right;
        }
    }

    class UnaryOp extends ASTNode {
        constructor(op, operand) {
            super();
            this.type = 'UnaryOp';
            this.op = op;  // 'NOT'
            this.operand = operand;
        }
    }

    class Literal extends ASTNode {
        constructor(value) {
            super();
            this.type = 'Literal';
            this.value = value;
        }
    }

    // ── Parser ──────────────────────────────────────────────────────────
    class Parser {
        constructor(tokens) {
            this.tokens = tokens;
            this.pos = 0;
        }

        peek(offset = 0) { return this.tokens[this.pos + offset]; }
        advance() { return this.tokens[this.pos++]; }
        current() { return this.peek(); }

        parse() {
            return this.parseOR();
        }

        parseOR() {
            let left = this.parseAND();
            while (this.current()?.type === TOKEN_TYPES.LOGICAL && this.current().value === 'OR') {
                this.advance(); // consume OR
                const right = this.parseAND();
                left = new BinaryOp('OR', left, right);
            }
            return left;
        }

        parseAND() {
            let left = this.parseNOT();
            while (this.current()?.type === TOKEN_TYPES.LOGICAL && this.current().value === 'AND') {
                this.advance(); // consume AND
                const right = this.parseNOT();
                left = new BinaryOp('AND', left, right);
            }
            return left;
        }

        parseNOT() {
            if (this.current()?.type === TOKEN_TYPES.LOGICAL && this.current().value === 'NOT') {
                this.advance(); // consume NOT
                const operand = this.parseNOT();
                return new UnaryOp('NOT', operand);
            }
            return this.parsePrimary();
        }

        parsePrimary() {
            // Parenthesized expression
            if (this.current()?.type === TOKEN_TYPES.PAREN_OPEN) {
                this.advance(); // consume (
                const expr = this.parseOR();
                if (this.current()?.type === TOKEN_TYPES.PAREN_CLOSE) {
                    this.advance(); // consume )
                }
                return expr;
            }

            // Comparison: field : value
            if (this.current()?.type === TOKEN_TYPES.FIELD) {
                const field = this.advance().value;
                const op = this.advance(); // should be OPERATOR (:)
                if (op?.type !== TOKEN_TYPES.OPERATOR) {
                    return new Literal(field);
                }

                // Collect value(s) - may include wildcards, escapes, pipes
                let operator = ':';
                let value = '';
                const valueTokens = [];

                while (this.current() && 
                       this.current().type !== TOKEN_TYPES.EOF &&
                       this.current().type !== TOKEN_TYPES.LOGICAL &&
                       this.current().type !== TOKEN_TYPES.PAREN_CLOSE &&
                       this.current().type !== TOKEN_TYPES.PAREN_OPEN) {

                    const tok = this.current();

                    if (tok.type === TOKEN_TYPES.PIPE) {
                        // Handle pipe operations: cmdline|regex or similar
                        this.advance();
                        const pipeOp = this.current()?.value;
                        operator = pipeOp ? `|${pipeOp}` : '|';
                        this.advance();
                        continue;
                    }

                    valueTokens.push(tok.value);
                    this.advance();
                }

                value = valueTokens.join('');

                // Parse value wildcards/escapes
                operator = this.parseOperatorFromValue(operator, value);

                return new Comparison(field, operator, this.cleanValue(value));
            }

            // Standalone value (fallback)
            if (this.current()?.type === TOKEN_TYPES.VALUE) {
                return new Literal(this.advance().value);
            }

            return new Literal('');
        }

        parseOperatorFromValue(baseOp, value) {
            if (baseOp.startsWith('|')) return baseOp; // pipe operations as-is

            // Check for wildcards in value - only * chars, not backslashes
            const hasLeadingWildcard = value.startsWith('*');
            const hasTrailingWildcard = value.endsWith('*');

            if (hasLeadingWildcard && hasTrailingWildcard) return '*:*';
            if (hasLeadingWildcard) return ':*';
            if (hasTrailingWildcard) return '*:';
            return ':';
        }

        cleanValue(value) {
            // Only remove leading/trailing wildcard asterisks, preserve backslashes
            let cleaned = value;
            // Remove leading *
            if (cleaned.startsWith('*')) {
                cleaned = cleaned.substring(1);
            }
            // Remove trailing *
            if (cleaned.endsWith('*')) {
                cleaned = cleaned.substring(0, cleaned.length - 1);
            }
            return cleaned;
        }
    }

    function buildAST(tokens) {
        const parser = new Parser(tokens);
        return parser.parse();
    }

    // ── AST Traversal ───────────────────────────────────────────────────
    function extractComparisons(ast, result = []) {
        if (!ast) return result;

        if (ast.type === 'Comparison') {
            result.push(ast);
        } else if (ast.type === 'BinaryOp') {
            extractComparisons(ast.left, result);
            extractComparisons(ast.right, result);
        } else if (ast.type === 'UnaryOp') {
            extractComparisons(ast.operand, result);
        }

        return result;
    }

    function walkAST(ast, callback) {
        if (!ast) return;

        if (ast.type === 'Comparison') {
            callback(ast, 'Comparison');
        } else if (ast.type === 'BinaryOp') {
            callback(ast, 'BinaryOp');
            walkAST(ast.left, callback);
            walkAST(ast.right, callback);
        } else if (ast.type === 'UnaryOp') {
            callback(ast, 'UnaryOp');
            walkAST(ast.operand, callback);
        } else if (ast.type === 'Literal') {
            callback(ast, 'Literal');
        }
    }

    // Public API
    return {
        tokenize,
        buildAST,
        extractComparisons,
        walkAST,
        NODE_TYPES: { Comparison, BinaryOp, UnaryOp, Literal },
    };
})();
