#!/usr/bin/env python3
"""Apply SimpleRose workstation baseline edits to cnspec policy bundles."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTENT = REPO / "content"


def remove_check_ref(content: str, uid: str) -> str:
    return content.replace(f"          - uid: {uid}\n", "")


def remove_query_block(content: str, uid: str) -> str:
    pattern = rf"  - uid: {re.escape(uid)}\n.*?(?=\n  - uid: |\Z)"
    return re.sub(pattern, "", content, flags=re.DOTALL)


def replace_once(content: str, old: str, new: str, label: str) -> str:
    if old not in content:
        raise ValueError(f"Expected block not found for {label}")
    return content.replace(old, new, 1)


def edit_windows(path: Path) -> str:
    content = path.read_text()
    content = content.replace("version: 0.4.2", "version: 0.5.0-simplerose")
    content = remove_check_ref(
        content, "mondoo-windows-workstation-security-antivirus-installed"
    )
    content = content.replace(
        "          - uid: mondoo-windows-workstation-security-automatic-update-is-enabled\n",
        "          - uid: mondoo-windows-workstation-security-automatic-update-is-enabled\n"
        "          - uid: simplerose-windows-workstation-security-crowdstrike-installed\n",
    )

    content = replace_once(
        content,
        """    mql: |
      registrykey.property(path: 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU', name: 'AUOptions') {
        data >= 4
      }
      registrykey.property(path: 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU', name: 'ScheduledInstallDay') {
        data == 0
      }
""",
        """    mql: |
      windows.services.where(name == "wuauserv").any(running)
        || registrykey.property(path: 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU', name: 'AUOptions') {
          data >= 4
        }
""",
        "windows automatic-update mql",
    )

    crowdstrike_query = """  - uid: simplerose-windows-workstation-security-crowdstrike-installed
    title: Ensure CrowdStrike Falcon is installed and running
    impact: 100
    tags:
      simplerose.com/category: endpoint-protection
    mql: |
      file("C:\\\\Program Files\\\\CrowdStrike\\\\CSFalconService.exe").exists
      windows.services.where(name == "CSFalconService").all(running)
    docs:
      desc: |
        Verifies CrowdStrike Falcon EDR is installed and the CSFalconService
        is running. Matches SimpleRose normalize (windows_normalize.ps1).
"""
    content = remove_query_block(
        content, "mondoo-windows-workstation-security-antivirus-installed"
    )
    content = content.rstrip() + "\n" + crowdstrike_query
    return content


def edit_linux(path: Path) -> str:
    content = path.read_text()
    content = content.replace("version: 1.1.1", "version: 1.2.0-simplerose")

    content = remove_check_ref(
        content,
        "mondoo-linux-workstation-security-permissions-on-bootloader-config-are-configured",
    )
    content = remove_query_block(
        content,
        "mondoo-linux-workstation-security-permissions-on-bootloader-config-are-configured",
    )

    # Drop BIOS group and query (not enforced by normalize).
    content = re.sub(
        r"      - title: BIOS Firmware up-to-date\n"
        r"        filters: \|\n"
        r"          asset\.family\.contains\('linux'\)\n"
        r"          package\('fwupd'\)\.installed\n"
        r"          packages\.where\(name == /xorg\|xserver\|wayland/i\)\.any\(installed\)\n"
        r"        checks:\n"
        r"          - uid: mondoo-linux-workstation-security-bios-uptodate\n",
        "",
        content,
    )
    content = remove_query_block(
        content, "mondoo-linux-workstation-security-bios-uptodate"
    )

    endpoint_group = """      - title: Endpoint protection
        filters: |
          asset.family.contains('linux')
          packages.where(name == /xorg|xserver|wayland/i).any(installed)
        checks:
          - uid: simplerose-linux-workstation-security-crowdstrike-installed
"""
    content = content.replace(
        "          - uid: mondoo-linux-workstation-security-root-and-home-are-encrypted\n"
        "      - title: BIOS Firmware up-to-date",
        "          - uid: mondoo-linux-workstation-security-root-and-home-are-encrypted\n"
        + endpoint_group,
    )
  # If BIOS group already removed, anchor after disk encryption group.
    if "simplerose-linux-workstation-security-crowdstrike-installed" not in content:
        content = content.replace(
            "          - uid: mondoo-linux-workstation-security-root-and-home-are-encrypted\n"
            "    scoring_system: highest impact",
            "          - uid: mondoo-linux-workstation-security-root-and-home-are-encrypted\n"
            + endpoint_group
            + "    scoring_system: highest impact",
        )

    crowdstrike_query = """  - uid: simplerose-linux-workstation-security-crowdstrike-installed
    title: Ensure CrowdStrike Falcon is installed and running
    impact: 90
    tags:
      simplerose.com/category: endpoint-protection
    mql: |
      file("/opt/CrowdStrike/falconctl").exists
      command("systemctl is-active falcon-sensor").stdout.trim == "active"
    docs:
      desc: |
        Matches linux_normalize.sh: falconctl present and falcon-sensor service active.
"""
    content = content.rstrip() + "\n" + crowdstrike_query
    return content


MAC_DROP_UIDS = [
    "mondoo-macos-security-disable-bonjour-advertising-service",
    "mondoo-macos-security-disable-remote-login",
    "mondoo-macos-security-enable-firewall-stealth-mode",
    "mondoo-macos-security-firewall-block-all-incoming",
    "mondoo-macos-security-enable-show-wifi-status",
    "mondoo-macos-security-ensure-airdrop-is-disabled",
    "mondoo-macos-security-ensure-macos-is-up-to-date",
    "mondoo-macos-security-password-age",
    "mondoo-macos-security-password-history",
    "mondoo-macos-security-set-a-minimum-password-length",
    "mondoo-macos-security-reduce-the-sudo-timeout-period",
    "mondoo-macos-security-enable-security-auditing",
    "mondoo-macos-security-ensure-security-auditing-retention",
    "mondoo-macos-security-retain-install-log-for-365-or-more-days",
    "mondoo-macos-security-software-updates-install-critical-updates",
]


def edit_macos(path: Path) -> str:
    content = path.read_text()
    content = content.replace("version: 1.4.3", "version: 1.5.0-simplerose")

    for uid in MAC_DROP_UIDS:
        content = remove_check_ref(content, uid)
        content = remove_query_block(content, uid)

    content = replace_once(
        content,
        """    mql: |
      macos.filevault.enabled == true
      users.where(name != /^_/ && shell != "/usr/bin/false" && name != "root") {
        name
        filePath = "/Library/Managed Preferences/" + name + "/complete.plist"
        a = file(filePath).exists == true && [filePath].where(file(_).exists) {
            parse.plist(filePath).params["com.apple.MCX"]["dontAllowFDEDisable"]["value"] == true
          }
        filePath2 = "/Library/Managed Preferences/com.apple.MCX.plist"
        b = file(filePath2).exists && parse.plist(filePath2).params['dontAllowFDEDisable'] == true
        a || b
      }
""",
        """    mql: |
      macos.filevault.enabled == true
""",
        "macos filevault mql",
    )

    content = replace_once(
        content,
        """    mql: |
      macos.gatekeeper.enabled == true
      users.where(name != /^_/ && shell != "/usr/bin/false" && name != "root") {
        name
        filePath1 = "/Library/Managed Preferences/" + name + "/complete.plist"
        a = file(filePath1).exists == true && [filePath1].where(file(_).exists) {
          parse.plist(filePath1).params["com.apple.systempolicy.control"]["AllowIdentifiedDevelopers"]["value"] == true
          parse.plist(filePath1).params["com.apple.systempolicy.control"]["EnableAssessment"]["value"] == true
        }
        filePath2 = "/Library/Managed Preferences/com.apple.systempolicy.control.plist"
        b = file(filePath2).exists == true && [filePath2].where(file(_).exists) {
          parse.plist(filePath2).params["AllowIdentifiedDevelopers"] == true
          parse.plist(filePath2).params["EnableAssessment"] == true
        }
        a || b
      }
""",
        """    mql: |
      macos.gatekeeper.enabled == true
""",
        "macos gatekeeper mql",
    )

    content = content.replace(
        "          - uid: mondoo-macos-security-ensure-macos-is-up-to-date\n",
        "          - uid: simplerose-macos-security-crowdstrike-installed\n",
    )
    if "simplerose-macos-security-crowdstrike-installed" not in content:
        content = content.replace(
            "          - uid: mondoo-macos-security-software-updates-automatic-download\n",
            "          - uid: mondoo-macos-security-software-updates-automatic-download\n"
            "          - uid: simplerose-macos-security-crowdstrike-installed\n",
        )

    crowdstrike_query = """  - uid: simplerose-macos-security-crowdstrike-installed
    title: Ensure CrowdStrike Falcon is installed and licensed
    impact: 80
    tags:
      simplerose.com/category: endpoint-protection
    mql: |
      file("/Applications/Falcon.app/Contents/Resources/falconctl").exists
      command("/Applications/Falcon.app/Contents/Resources/falconctl stats 2>/dev/null").stdout.contains("customerID:")
    docs:
      desc: |
        Matches mac_normalize.sh: Falcon.app installed and falconctl reports licensed CID.
"""
    content = content.rstrip() + "\n" + crowdstrike_query
    return content


def main() -> None:
    edits = {
        CONTENT / "mondoo-windows-workstation-security.mql.yaml": edit_windows,
        CONTENT / "mondoo-linux-workstation-security.mql.yaml": edit_linux,
        CONTENT / "mondoo-macos-security.mql.yaml": edit_macos,
    }
    for path, fn in edits.items():
        path.write_text(fn(path))
        print(f"updated {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()
