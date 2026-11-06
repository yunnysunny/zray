import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import tarfile
import time


ARCHITECTURES = {
    "mipsel_24kc": ("MIPS", "LSB"),
    "mips_24kc": ("MIPS", "MSB"),
    "aarch64_generic": ("ARM aarch64", "LSB"),
    "arm_cortex-a7_neon-vfpv4": ("ARM", "LSB"),
    "x86_64": ("x86-64", "LSB"),
}
BUILD_TIME = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.GNU_FORMAT) as result:
        directories = sorted({str(parent) for name, _, _ in entries for parent in pathlib.PurePosixPath(name).parents if str(parent) != "."}, key=lambda name: (name.count("/"), name))
        for name in directories:
            entry = tarfile.TarInfo("./" + name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            entry.mtime = BUILD_TIME
            result.addfile(entry)
        for name, data, mode in entries:
            entry = tarfile.TarInfo("./" + name)
            entry.size = len(data)
            entry.mode = mode
            entry.mtime = BUILD_TIME
            result.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


def build(binary, architecture, version, destination):
    root = pathlib.Path(__file__).resolve().parents[1]
    file_type = subprocess.run(["file", "-b", str(binary)], text=True, capture_output=True, check=True).stdout
    if not all(part in file_type for part in ARCHITECTURES[architecture]):
        raise ValueError(f"程序架构与 {architecture} 不符：{file_type.strip()}")
    if not re.fullmatch(r"[0-9A-Za-z.+~_-]+", version):
        raise ValueError("软件包版本格式不正确")
    if not binary.is_file() or binary.stat().st_size == 0:
        raise ValueError("Zray 程序不存在或为空")
    payload = [("mnt/zray/zray", binary.read_bytes(), 0o755)]
    view_name = "client_" + re.sub(r"[^A-Za-z0-9_]", "_", version)
    app = root / "luci-app-zray"
    for path in sorted((app / "root").rglob("*")):
        if not path.is_file():
            continue
        target = path.relative_to(app / "root").as_posix()
        mode = 0o755 if target.startswith(("etc/init.d/", "usr/libexec/")) else 0o600 if target == "etc/config/zray" else 0o644
        content = path.read_bytes()
        if target == "usr/share/luci/menu.d/luci-app-zray.json":
            menu = json.loads(content)
            menu["admin/services/zray"]["action"]["path"] = "zray/" + view_name
            content = json.dumps(menu, ensure_ascii=False).encode()
        payload.append((target, content, mode))
    for path in sorted((app / "htdocs").rglob("*")):
        if path.is_file():
            target = "www/" + path.relative_to(app / "htdocs").as_posix()
            if target.endswith("/view/zray/client.js"):
                target = target[:-len("client.js")] + view_name + ".js"
            payload.append((target, path.read_bytes(), 0o644))
    payload.append(("usr/share/licenses/zray/LICENSE", (root / "LICENSE").read_bytes(), 0o644))
    data = archive(payload)
    control = (
        "Package: zray\n"
        f"Version: {version}\n"
        f"Architecture: {architecture}\n"
        "Maintainer: tianpeng-dev\n"
        "Section: net\n"
        "Priority: optional\n"
        "License: MIT\n"
        "Provides: luci-app-zray\n"
        "Depends: luci-base, rpcd, ucode, ucode-mod-fs, ucode-mod-uci, ucode-mod-ubus, https-dns-proxy, curl, flock\n"
        f"Installed-Size: {len(gzip.decompress(data))}\n"
        "Description: Zray with LuCI node import, service control and TCP transparent proxy.\n"
    ).encode()
    metadata = [("control", control, 0o644), ("conffiles", b"/etc/config/zray\n", 0o644)]
    metadata.extend((name, (app / name).read_bytes(), 0o755) for name in ["preinst", "postinst", "prerm"])
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"zray_{version}_{architecture}.ipk"
    output.write_bytes(archive([("debian-binary", b"2.0\n", 0o644), ("data.tar.gz", data, 0o644), ("control.tar.gz", archive(metadata), 0o644)]))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".ipk.sha256").write_text(f"{digest}  {output.name}\n")
    with tarfile.open(output, mode="r:gz") as package:
        with tarfile.open(fileobj=package.extractfile("./data.tar.gz"), mode="r:gz") as contents:
            assert contents.getmember("./etc/config/zray").mode == 0o600
            assert contents.getmember("./usr/libexec/rpcd/zray").mode == 0o755
            assert contents.extractfile("./mnt/zray/zray").read() == binary.read_bytes()
            menu = json.loads(contents.extractfile("./usr/share/luci/menu.d/luci-app-zray.json").read())
            view_path = menu["admin/services/zray"]["action"]["path"]
            assert contents.getmember("./www/luci-static/resources/view/" + view_path + ".js").isfile()
    print(output)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="生成包含 Zray 程序及 LuCI 界面的 OpenWrt 软件包")
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--arch", required=True, choices=ARCHITECTURES)
    parser.add_argument("--version", default="0.2.0-15")
    parser.add_argument("--output", default="dist", type=pathlib.Path)
    arguments = parser.parse_args()
    build(arguments.binary.resolve(), arguments.arch, arguments.version, arguments.output.resolve())
