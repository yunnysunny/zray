export function access(path) { return !!recovery_test_context.backupPresent; }
export function readfile(path) { return null; }
export function writefile(path, data) {
    if (recovery_test_context.allowWrites) return length(data);
    die('Unexpected filesystem write in failure test');
}
