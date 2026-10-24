from __future__ import annotations

from commandcompass.rules.base import Rule
from commandcompass.rules.destructive import (
    FormatStorageRule,
    GitDestructiveRule,
    OverwriteRedirectionRule,
    RecursiveDeleteRule,
)
from commandcompass.rules.network import NetworkActivityRule
from commandcompass.rules.obfuscation import ObfuscationRule
from commandcompass.rules.persistence import PersistenceRule
from commandcompass.rules.privilege import (
    PermissionChangeRule,
    PrivilegeElevationRule,
    SecuritySensitivePathRule,
)
from commandcompass.rules.remote_exec import DownloadAndExecuteRule, RemoteScriptInvocationRule
from commandcompass.rules.secrets import PrivateKeyPathRule, SecretExposureRule
from commandcompass.rules.supply_chain import SupplyChainRule


def default_rules() -> list[Rule]:
    return [
        RecursiveDeleteRule(),
        FormatStorageRule(),
        GitDestructiveRule(),
        OverwriteRedirectionRule(),
        PrivilegeElevationRule(),
        PermissionChangeRule(),
        SecuritySensitivePathRule(),
        DownloadAndExecuteRule(),
        RemoteScriptInvocationRule(),
        SecretExposureRule(),
        PrivateKeyPathRule(),
        NetworkActivityRule(),
        PersistenceRule(),
        ObfuscationRule(),
        SupplyChainRule(),
    ]


def rule_by_id(rule_id: str) -> Rule | None:
    for r in default_rules():
        if r.metadata.id == rule_id:
            return r
    # allow suffix variants? no
    return None
