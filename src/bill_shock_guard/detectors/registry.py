"""Detector and action discovery registry."""

import importlib
import pkgutil
from typing import Dict, List, Tuple

import bill_shock_guard.detectors
from bill_shock_guard.interfaces import Action, Detector
from bill_shock_guard.models import ActionKind


def discover() -> Tuple[List[Detector], Dict[ActionKind, Action]]:
    """Import every module in bill_shock_guard.detectors and collect DETECTORS and ACTIONS."""
    detectors: List[Detector] = []
    actions: Dict[ActionKind, Action] = {}

    package = bill_shock_guard.detectors
    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
        if is_pkg or module_name == "registry":
            continue
        full_module_name = f"{package.__name__}.{module_name}"
        try:
            mod = importlib.import_module(full_module_name)
        except Exception:
            # Skip unimportable modules during partial build phases
            continue

        mod_detectors = getattr(mod, "DETECTORS", [])
        for d in mod_detectors:
            detectors.append(d)

        mod_actions = getattr(mod, "ACTIONS", {})
        if isinstance(mod_actions, dict):
            for k, a in mod_actions.items():
                if isinstance(k, ActionKind):
                    actions[k] = a
                elif isinstance(k, str):
                    try:
                        actions[ActionKind(k)] = a
                    except ValueError:
                        pass

    return detectors, actions
