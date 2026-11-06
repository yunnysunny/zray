import argparse
import pathlib
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--ucode", default="ucode")
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
modules = root / "luci-app-zray/root/usr/share/ucode"
targets = list((root / "luci-app-zray/root").rglob("*.uc"))
targets.append(root / "luci-app-zray/root/usr/libexec/rpcd/zray")
targets.append(root / "luci-app-zray/root/usr/libexec/zray-ui-restart")
temporary = root / ".scratch"
temporary.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=temporary) as output:
    for index, path in enumerate(targets):
        flags = "-cdynlink=fs,dynlink=uci,dynlink=ubus,dynlink=zray_ui,dynlink=zray_policy,dynlink=zray_monitor,dynlink=zray_manage,dynlink=zray_recovery"
        if path.parent == modules:
            flags += ",module"
        subprocess.run([args.ucode, flags,
                        "-o", str(pathlib.Path(output) / str(index)), str(path)], check=True)
for test in sorted((root / "tests").glob("*.test.uc")):
    search = ["-L", str(modules / "*.uc")]
    if test.name.endswith(".integration.test.uc"):
        search = ["-L", str(root / "tests/fixtures/recovery/*.uc")] + search
    subprocess.run([args.ucode, *search, str(test)], check=True)
print(f"Compiled {len(targets)} ucode sources; all ucode tests passed")
