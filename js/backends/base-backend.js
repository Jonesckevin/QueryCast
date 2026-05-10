/**
 * base-backend.js
 * Abstract base class for all SIEM conversion backends.
 * Provides the core condition AST → query fragment walker.
 *
 * Subclasses must implement:
 *   - mapField(fieldName)            → string (backend field name or null)
 *   - buildFieldCondition(node)      → string (one field=value expression)
 *   - buildKeywords(values)          → string (keyword search expression)
 *   - andExpr(a, b)                  → string
 *   - orExpr(a, b)                   → string
 *   - notExpr(a)                     → string
 *   - wrapGroup(expr)                → string (parenthesise group)
 *   - buildHeader(sigmaRule)         → string (logsource header / table prefix)
 *   - buildFooter(sigmaRule)         → string (optional footer / comments)
 */
'use strict';

class BaseBackend {
    constructor(options = {}) {
        this.options = options;
    }

    // ── Main entry point ────────────────────────────────────────────────
    convert(sigmaRule) {
        // Reset per-conversion tracking
        this._skippedFields = [];

        const header = this.buildHeader(sigmaRule);
        const body   = this._resolveConditionAst(sigmaRule.detection.conditionAst, sigmaRule);
        const footer = this.buildFooter(sigmaRule);

        // Build a warning if any fields were silently dropped
        let warning = '';
        if (this._skippedFields.length > 0) {
            const unique = [...new Set(this._skippedFields)];
            const bodyEmpty = !body || !body.trim();
            if (bodyEmpty) {
                warning = this._makeComment(
                    `\u26a0\ufe0f WARNING: All detection filters were removed — ` +
                    `the following fields are not supported for this SIEM: ${unique.join(', ')}. ` +
                    `No conditions remain in the output.`
                );
            } else {
                warning = this._makeComment(
                    `\u26a0\ufe0f Note: ${unique.length} field(s) not supported for this SIEM ` +
                    `and were removed: ${unique.join(', ')}`
                );
            }
        }

        const parts = [warning, header, body, footer].filter(p => p && p.trim() !== '');
        return parts.join('\n');
    }

    // ── Walk the condition AST and produce query string ─────────────────
    _resolveConditionAst(node, sigmaRule) {
        switch (node.type) {

            case 'ref': {
                const idName = node.name;
                // Find the identifier block (case-insensitive)
                const key = Object.keys(sigmaRule.detection.identifiers)
                    .find(k => k.toLowerCase() === idName.toLowerCase());
                if (!key) {
                    return this._makeComment(`WARNING: unknown identifier "${idName}"`);
                }
                const idNode = sigmaRule.detection.identifiers[key];
                return this._resolveIdentifier(idNode, sigmaRule);
            }

            case 'and':
                return this._binOp('and', node, sigmaRule);

            case 'or':
                return this._binOp('or', node, sigmaRule);

            case 'not': {
                const inner = this._resolveConditionAst(node.expr, sigmaRule);
                return this.notExpr(inner);
            }

            case 'all_of': {
                // All named identifiers must match
                const parts = node.identifiers.map(id => {
                    const idNode = sigmaRule.detection.identifiers[
                        Object.keys(sigmaRule.detection.identifiers).find(k => k.toLowerCase() === id.toLowerCase())
                    ];
                    return this._resolveIdentifier(idNode, sigmaRule);
                }).filter(Boolean);
                if (parts.length === 0) return this._makeComment('WARNING: all_of matched no identifiers');
                return parts.reduce((acc, p) => this.andExpr(acc, p));
            }

            case 'any_of': {
                // Any of the named identifiers must match
                const parts = node.identifiers.map(id => {
                    const idNode = sigmaRule.detection.identifiers[
                        Object.keys(sigmaRule.detection.identifiers).find(k => k.toLowerCase() === id.toLowerCase())
                    ];
                    return this._resolveIdentifier(idNode, sigmaRule);
                }).filter(Boolean);
                if (parts.length === 0) return this._makeComment('WARNING: any_of matched no identifiers');
                return parts.reduce((acc, p) => this.orExpr(acc, p));
            }

            default:
                return this._makeComment(`WARNING: unknown condition node type "${node.type}"`);
        }
    }

    _binOp(op, node, sigmaRule) {
        const left  = this._resolveConditionAst(node.left,  sigmaRule);
        const right = this._resolveConditionAst(node.right, sigmaRule);
        return op === 'and' ? this.andExpr(left, right) : this.orExpr(left, right);
    }

    // ── Resolve a detection identifier node ─────────────────────────────
    _resolveIdentifier(node, sigmaRule) {
        if (!node) return '';

        switch (node.type) {
            case 'field_condition': {
                const result = this.buildFieldCondition(node, sigmaRule.logsource);
                if (!result) {
                    // buildFieldCondition returned null/'' → field unsupported; track it
                    this._skippedFields = this._skippedFields || [];
                    this._skippedFields.push(node.field);
                    return '';
                }
                return result;
            }

            case 'and_conditions': {
                const parts = node.conditions
                    .map(c => this._resolveIdentifier(c, sigmaRule))
                    .filter(Boolean);
                if (parts.length === 0) return '';
                if (parts.length === 1) return parts[0];
                const combined = parts.reduce((a, b) => this.andExpr(a, b));
                return this.wrapGroup(combined);
            }

            case 'or_conditions': {
                const parts = node.conditions
                    .map(c => this._resolveIdentifier(c, sigmaRule))
                    .filter(Boolean);
                if (parts.length === 0) return '';
                if (parts.length === 1) return parts[0];
                const combined = parts.reduce((a, b) => this.orExpr(a, b));
                return this.wrapGroup(combined);
            }

            case 'keywords':
                return this.buildKeywords(node.values, sigmaRule.logsource);

            default:
                return this._makeComment(`WARNING: unknown identifier node type "${node.type}"`);
        }
    }

    // ─── Default implementations (override in subclasses as needed) ──────

    buildHeader(sigmaRule)  { return ''; }
    buildFooter(sigmaRule)  { return ''; }

    // Build a field condition node into a query string fragment
    buildFieldCondition(node, logsource) {
        throw new Error(`${this.constructor.name} must implement buildFieldCondition()`);
    }

    buildKeywords(values, logsource) {
        throw new Error(`${this.constructor.name} must implement buildKeywords()`);
    }

    andExpr(a, b)   { return `${a} AND ${b}`; }
    orExpr(a, b)    { return `${a} OR ${b}`; }
    notExpr(a)      { return `NOT ${a}`; }
    wrapGroup(a)    { return `(${a})`; }

    _makeComment(text) { return `/* ${text} */`; }

    // ─── Helper: build a single field=value pair from modifiers ──────────
    // Returns an array of raw value expressions (before OR-joining)
    _applyModifiers(rawValues, modifiers, logsource) {
        // modifiers is an array like ['contains'], ['startswith'], ['endswith'], ['re'], ['cidr']
        // returns array of {modifier, value} for the backend to render
        return rawValues.map(v => ({
            modifier: modifiers.length > 0 ? modifiers[0] : 'equals',
            extraMods: modifiers.slice(1),
            value: v
        }));
    }
}
