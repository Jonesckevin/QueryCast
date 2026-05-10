/**
 * recipe.js
 * Recipe management – maintains the ordered list of active operators
 * and handles execution of the pipeline against the current input.
 */
'use strict';

const Recipe = (() => {
    // Internal state
    let _steps     = [];   // Array of { id: string, stepId: string, opId: string, opts: {} }
    let _stepIdSeq = 0;
    let _onChange  = null; // Callback: (steps) => void

    function onChangeCallback(fn) {
        _onChange = fn;
    }

    function _notify() {
        if (_onChange) _onChange([..._steps]);
    }

    // ── CRUD ─────────────────────────────────────────────────────────────

    function addStep(operatorId) {
        const op = OperatorsRegistry.getById(operatorId);
        if (!op) return null;

        // Build default option values
        const opts = {};
        (op.options || []).forEach(o => { opts[o.id] = o.default; });

        const step = {
            stepId: `step-${++_stepIdSeq}`,
            opId:   operatorId,
            opts,
            disabled: false,
        };
        _steps.push(step);
        _notify();
        return step;
    }

    function removeStep(stepId) {
        _steps = _steps.filter(s => s.stepId !== stepId);
        _notify();
    }

    function moveStep(stepId, direction) {
        const idx = _steps.findIndex(s => s.stepId === stepId);
        if (idx === -1) return;
        const target = direction === 'up' ? idx - 1 : idx + 1;
        if (target < 0 || target >= _steps.length) return;
        [_steps[idx], _steps[target]] = [_steps[target], _steps[idx]];
        _notify();
    }

    function setOption(stepId, optionId, value) {
        const step = _steps.find(s => s.stepId === stepId);
        if (step) {
            step.opts[optionId] = value;
            _notify();
        }
    }

    function toggleDisabled(stepId) {
        const step = _steps.find(s => s.stepId === stepId);
        if (step) {
            step.disabled = !step.disabled;
            _notify();
        }
    }

    function clear() {
        _steps = [];
        _notify();
    }

    function getSteps() { return [..._steps]; }

    // ── Execution ─────────────────────────────────────────────────────────
    // Runs each enabled step in sequence.
    // Returns array of { stepId, output, error, durationMs }
    function run(input, initialFormat = 'sigma') {
        const results = [];
        let current = input;
        let currentFormat = initialFormat;

        for (const step of _steps) {
            if (step.disabled) {
                results.push({ stepId: step.stepId, output: current, error: null, skipped: true });
                continue;
            }

            const op = OperatorsRegistry.getById(step.opId);
            if (!op) {
                results.push({ stepId: step.stepId, output: current, error: `Unknown operator: ${step.opId}`, skipped: false });
                continue;
            }

            const t0 = performance.now();
            try {
                if (op.fromFormat && op.fromFormat !== currentFormat) {
                    throw new Error(`Step expects ${op.fromFormat.toUpperCase()} input, but current output is ${currentFormat.toUpperCase()}.`);
                }

                const output = op.run(current, step.opts);
                const durationMs = Math.round(performance.now() - t0);
                results.push({
                    stepId: step.stepId,
                    output,
                    error: null,
                    skipped: false,
                    durationMs,
                    fromFormat: currentFormat,
                    toFormat: op.toFormat || currentFormat,
                });
                current = output;
                currentFormat = op.toFormat || currentFormat;
            } catch (err) {
                const durationMs = Math.round(performance.now() - t0);
                results.push({
                    stepId: step.stepId,
                    output: `/* ERROR: ${err.message} */`,
                    error: err.message,
                    skipped: false,
                    durationMs,
                    fromFormat: currentFormat,
                    toFormat: currentFormat,
                });
                // Continue with previous output so later steps may still attempt
            }
        }

        return { results, finalOutput: current, finalFormat: currentFormat };
    }

    return {
        onChangeCallback,
        addStep,
        removeStep,
        moveStep,
        setOption,
        toggleDisabled,
        clear,
        getSteps,
        run,
    };
})();
