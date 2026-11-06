// Used only by the isolated apply integration test. No system configuration.
export const state_path = '/__zray_isolated_test_no_state__';
export function settings() { return recovery_test_context.config; }
export function state() { return {}; }
export function write_state(value) { push(recovery_test_context.states, value); }
export function live(name) { return !!recovery_test_context.live; }
export function rules_active() { return false; }
export function checked(ok, message) { if (!ok) die(message); return ok; }
export function runtime_config() { die('unexpected runtime config call'); }
