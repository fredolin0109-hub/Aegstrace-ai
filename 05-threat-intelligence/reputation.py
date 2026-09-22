from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from providers.base import ProviderResult
from domain_info import DomainMetadata


@dataclass
class CompositeReputation:
    composite_score: float
    verdict: str  # SAFE, SUSPICIOUS, HIGH_RISK
    confidence: float
    indicators: List[Dict[str, Any]]
    active_sources: List[str]
    source_weights: Dict[str, float]


class ReputationEngine:
    """
    Computes calibrated composite threat reputation scores from multiple
    heterogeneous threat intelligence sources, applying dynamic weighting,
    confidence calibration, and override rules for high-certainty indicators.
    """

    DEFAULT_WEIGHTS = {
        "virustotal": 0.35,
        "abuseipdb": 0.30,
        "local_dsa": 0.25,
        "alienvault_otx": 0.20,
        "urlscan": 0.20,
    }

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if custom_weights:
            self.weights.update(custom_weights)

    def calculate(
        self,
        results: List[ProviderResult],
        domain_meta: Optional[DomainMetadata] = None,
    ) -> CompositeReputation:
        """
        Fuses provider results into a single composite score and security verdict.
        """
        active_results = [r for r in results if r.available and r.confidence > 0.0]
        indicators: List[Dict[str, Any]] = []
        active_sources: List[str] = [r.source_name for r in active_results]
        applied_weights: Dict[str, float] = {}

        if not active_results:
            # Baseline neutral result when no external feeds responded
            return CompositeReputation(
                composite_score=0.05,
                verdict="SAFE",
                confidence=0.50,
                indicators=[],
                active_sources=[],
                source_weights={},
            )

        # Check for enterprise allowlist safe override first
        is_known_safe = any(
            r.source_name == "local_dsa"
            and not r.is_malicious
            and r.confidence >= 0.98
            and "TRUSTED_ALLOWLIST" in r.categories
            for r in active_results
        )

        has_authoritative_malicious = any(
            r.is_malicious and r.threat_score >= 0.85 and r.confidence >= 0.85
            for r in active_results
        )

        if is_known_safe and not has_authoritative_malicious:
            return CompositeReputation(
                composite_score=0.0,
                verdict="SAFE",
                confidence=0.99,
                indicators=[{
                    "type": "ALLOWLIST_DOMAIN",
                    "source": "local_dsa",
                    "severity": "INFO",
                    "details": {"description": "Domain verified against enterprise trusted allowlist"},
                }],
                active_sources=active_sources,
                source_weights={s: 1.0 for s in active_sources},
            )

        # Collect indicators and compute weighted sum
        weighted_score_sum = 0.0
        weighted_conf_sum = 0.0
        malicious_count = 0
        max_malicious_score = 0.0

        for r in active_results:
            w = self.weights.get(r.source_name, 0.20)
            applied_weights[r.source_name] = w

            effective_weight = w * r.confidence
            weighted_score_sum += r.threat_score * effective_weight
            weighted_conf_sum += effective_weight

            if r.is_malicious:
                malicious_count += 1
                max_malicious_score = max(max_malicious_score, r.threat_score)
                indicators.append({
                    "type": "PROVIDER_THREAT_DETECTION",
                    "source": r.source_name,
                    "severity": "HIGH" if r.threat_score >= 0.70 else "MEDIUM",
                    "details": {
                        "threat_score": r.threat_score,
                        "confidence": r.confidence,
                        "categories": r.categories,
                    },
                })

        composite_score = (
            (weighted_score_sum / weighted_conf_sum)
            if weighted_conf_sum > 0
            else 0.05
        )

        # 1. Authoritative Malicious Override & Consensus Protection: Prevent dilution of verified threats
        if has_authoritative_malicious:
            composite_score = max(composite_score, 0.75, max_malicious_score * 0.90)
        elif malicious_count >= 2 and max_malicious_score >= 0.70:
            composite_score = max(composite_score, 0.70, max_malicious_score * 0.85)

        # 2. Domain Heuristics Fusion
        if domain_meta:
            heuristic_delta = 0.0
            if domain_meta.is_suspicious_tld:
                indicators.append({
                    "type": "SUSPICIOUS_TLD",
                    "source": "domain_resolver",
                    "severity": "MEDIUM",
                    "details": {"tld": domain_meta.tld},
                })
                heuristic_delta += 0.15

            if domain_meta.is_high_entropy:
                indicators.append({
                    "type": "HIGH_ENTROPY_DOMAIN",
                    "source": "domain_resolver",
                    "severity": "LOW",
                    "details": {"entropy": domain_meta.entropy},
                })
                heuristic_delta += 0.10

            if domain_meta.is_ip:
                indicators.append({
                    "type": "RAW_IP_TARGET",
                    "source": "domain_resolver",
                    "severity": "HIGH",
                    "details": {"ip": domain_meta.domain},
                })
                heuristic_delta += 0.20

            if domain_meta.heuristics.get("suspicious_nameservers"):
                indicators.append({
                    "type": "SUSPICIOUS_NAMESERVERS",
                    "source": "domain_resolver",
                    "severity": "MEDIUM",
                    "details": {"nameservers": domain_meta.nameservers},
                })
                heuristic_delta += 0.15

            if heuristic_delta > 0:
                # Apply capped heuristic penalty to avoid runaway scores without external feed confirmation
                composite_score = min(0.85, composite_score + min(0.35, heuristic_delta))

        # Clamp composite score between 0.0 and 1.0
        final_score = round(min(1.0, max(0.0, composite_score)), 4)

        # Classification
        if final_score >= 0.70:
            verdict = "HIGH_RISK"
        elif final_score >= 0.35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # Calibrate confidence based on provider agreement
        total_providers = len(active_results)
        if total_providers == 1:
            calibrated_conf = active_results[0].confidence * 0.90
        elif malicious_count == total_providers or malicious_count == 0:
            # Full consensus
            avg_conf = sum(r.confidence for r in active_results) / total_providers
            calibrated_conf = min(0.99, avg_conf + 0.05)
        else:
            # Divergent opinions
            calibrated_conf = 0.75

        return CompositeReputation(
            composite_score=final_score,
            verdict=verdict,
            confidence=round(calibrated_conf, 4),
            indicators=indicators,
            active_sources=active_sources,
            source_weights=applied_weights,
        )


default_reputation_engine = ReputationEngine()
