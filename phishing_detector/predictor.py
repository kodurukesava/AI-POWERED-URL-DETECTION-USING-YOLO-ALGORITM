from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .features import extract_url_features, url_risk_reason
from .model import ModelBundle, load_or_train_model
from .vision import analyze_image


@dataclass(frozen=True)
class PredictionResult:
    label: str
    score: float
    url_score: float
    visual_score: float
    reasons: list[str]
    metrics: dict[str, float]


class PhishingDetector:
    def __init__(self, bundle: ModelBundle | None = None) -> None:
        self.bundle = bundle or load_or_train_model()

    def predict(self, url: str, image_path: str | Path | None = None) -> PredictionResult:
        url_features = extract_url_features(url)
        proba = float(self.bundle.model.predict_proba([url_features.values])[0][1])
        heuristic_score, heuristic_reasons = url_risk_reason(url_features.mapping)
        critical_flags = url_features.mapping

        visual_score = 0.0
        visual_reasons: list[str] = []
        if image_path:
            visual_result = analyze_image(image_path)
            visual_score = visual_result.risk_score
            visual_reasons = visual_result.reasons

        risk_score = 0.25 * proba + 0.65 * heuristic_score + 0.10 * visual_score
        if heuristic_score >= 0.6:
            risk_score = max(risk_score, 0.8)
        if visual_score >= 0.5:
            risk_score = max(risk_score, 0.68)
        if critical_flags["having_ip_address"] == -1 or critical_flags["having_at_symbol"] == -1:
            risk_score = max(risk_score, 0.88)
        if critical_flags["shortining_service"] == -1:
            risk_score = max(risk_score, 0.75)
        if critical_flags["sslfinal_state"] == -1 and critical_flags["having_sub_domain"] == -1:
            risk_score = max(risk_score, 0.78)
        if critical_flags["abnormal_url"] == -1 or critical_flags["dnsrecord"] == -1:
            risk_score = max(risk_score, 0.82)
        if critical_flags["statistical_report"] == -1:
            risk_score = max(risk_score, 0.86)
        risk_score = float(np.clip(risk_score, 0.0, 1.0))

        severe_flags = sum(
            1
            for key in (
                "having_ip_address",
                "having_at_symbol",
                "shortining_service",
                "abnormal_url",
                "dnsrecord",
                "statistical_report",
            )
            if critical_flags[key] == -1
        )
        moderate_flags = sum(
            1
            for key in (
                "double_slash_redirecting",
                "prefix_suffix",
                "having_sub_domain",
                "sslfinal_state",
                "https_token",
                "request_url",
                "url_of_anchor",
                "sfh",
                "redirect",
                "iframe",
            )
            if critical_flags[key] == -1
        )

        label = "Phishing" if (
            severe_flags >= 1 and (heuristic_score >= 0.15 or risk_score >= 0.5)
        ) or (
            severe_flags >= 2
        ) or (
            heuristic_score >= 0.45
        ) or (
            risk_score >= 0.72
        ) or (
            critical_flags["sslfinal_state"] == -1 and critical_flags["having_sub_domain"] == -1 and moderate_flags >= 1
        ) else "Legitimate"
        confidence = risk_score if label == "Phishing" else 1.0 - risk_score
        confidence = float(np.clip(confidence, 0.0, 1.0))
        reasons = heuristic_reasons + visual_reasons
        if not reasons:
            reasons.append("No strong phishing indicators were detected")
        if url_features.fetch_error:
            reasons.append("Could not fully inspect the website content, so the decision is URL-heavy")

        return PredictionResult(
            label=label,
            score=confidence,
            url_score=proba,
            visual_score=visual_score,
            reasons=reasons,
            metrics=self.bundle.metrics,
        )
