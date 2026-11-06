// Cleanup must continue after a failed step: restoring ordinary Internet access
// must never depend on successfully stopping a different service.
export function run_steps(steps) {
    const errors = [];
    for (let step in steps) {
        try {
            if (!step.run()) push(errors, step.label);
        }
        catch (error) {
            push(errors, step.label + '：' + error.message);
        }
    }
    return errors;
};
