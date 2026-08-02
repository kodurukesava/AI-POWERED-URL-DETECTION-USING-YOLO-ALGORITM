from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np

try:
    from ultralytics import YOLO
except Exception:  # pragma: no cover
    YOLO = None

YOLO_CLASS_HINTS = {
    "laptop",
    "tv",
    "cell phone",
    "keyboard",
    "mouse",
    "remote",
    "person",
}


@dataclass(frozen=True)
class VisualResult:
    risk_score: float
    reasons: list[str]
    features: dict[str, float]


_YOLO_MODEL = None


def _load_yolo():
    global _YOLO_MODEL
    if YOLO is None:
        return None
    if _YOLO_MODEL is None:
        try:
            _YOLO_MODEL = YOLO("yolov8n.pt")
        except Exception:
            _YOLO_MODEL = None
    return _YOLO_MODEL


def _layout_features(image: np.ndarray) -> dict[str, float]:
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blurred, 50, 150)
    edge_density = float(np.mean(edges > 0))

    _, thresh = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    white_ratio = float(np.mean(thresh > 240))

    contours, _ = cv2.findContours(255 - thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    rect_like = 0
    large_rect_like = 0
    for contour in contours:
        x, y, w, h = cv2.boundingRect(contour)
        area = w * h
        if area < 250:
            continue
        aspect = w / max(1, h)
        if 1.8 <= aspect <= 12 or 0.08 <= aspect <= 0.55:
            rect_like += 1
            if area > image.shape[0] * image.shape[1] * 0.01:
                large_rect_like += 1

    return {
        "edge_density": edge_density,
        "white_ratio": white_ratio,
        "rect_like": float(rect_like),
        "large_rect_like": float(large_rect_like),
        "contour_count": float(len(contours)),
        "image_width": float(image.shape[1]),
        "image_height": float(image.shape[0]),
    }


def analyze_image(image_path: str | Path) -> VisualResult:
    path = Path(image_path)
    if not path.exists():
        return VisualResult(0.0, ["Screenshot file was not found"], {})

    image = cv2.imread(str(path))
    if image is None:
        return VisualResult(0.0, ["Screenshot could not be read"], {})

    features = _layout_features(image)
    reasons: list[str] = []
    score = 0.0

    if features["white_ratio"] > 0.55 and features["rect_like"] >= 5:
        score += 0.18
        reasons.append("The page layout looks like a simple form or landing page")
    if features["edge_density"] < 0.03 and features["rect_like"] >= 3:
        score += 0.12
        reasons.append("The screenshot has a low-complexity layout with form-like regions")
    if features["large_rect_like"] >= 2:
        score += 0.10
        reasons.append("Multiple large rectangular regions were detected")

    yolo_model = _load_yolo()
    if yolo_model is not None:
        try:
            results = yolo_model.predict(source=str(path), verbose=False)
            if results:
                result = results[0]
                boxes = result.boxes
                if boxes is not None and len(boxes) > 0:
                    names = result.names
                    class_counts: dict[str, int] = {}
                    confidences = []
                    for cls_id, conf in zip(boxes.cls.tolist(), boxes.conf.tolist()):
                        name = names[int(cls_id)]
                        class_counts[name] = class_counts.get(name, 0) + 1
                        confidences.append(float(conf))

                    ui_hits = sum(class_counts.get(name, 0) for name in YOLO_CLASS_HINTS)
                    if ui_hits:
                        score += min(0.12, ui_hits * 0.04)
                        reasons.append("YOLO detected screen-related objects in the screenshot")
                    if confidences:
                        score += min(0.08, float(np.mean(confidences)) * 0.08)
                else:
                    reasons.append("YOLO loaded successfully but found no strong object detections")
        except Exception:
            reasons.append("YOLO analysis was unavailable for this image")

    score = max(0.0, min(1.0, score))
    return VisualResult(score, reasons, features)

