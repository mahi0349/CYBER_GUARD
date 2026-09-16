"""
CYBERGUARD Scenario C: Account Takeover & Anomaly Detection Module.
"""

from .anomaly_model import (
    AnomalyModel,
    calculate_geo_velocity,
    calculate_haversine_distance,
)
from .detector import AccountAnomalyDetector
from .explainer import AccountExplainer
from .log_generator import SyntheticLogGenerator
from .mitre_mapper import MitreAccountMapper

__all__ = [
    "AccountAnomalyDetector",
    "SyntheticLogGenerator",
    "AnomalyModel",
    "MitreAccountMapper",
    "AccountExplainer",
    "calculate_haversine_distance",
    "calculate_geo_velocity",
]
