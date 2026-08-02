from __future__ import annotations

import argparse
from pathlib import Path

from .gui import PhishingApp
from .predictor import PhishingDetector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-powered phishing detection")
    parser.add_argument("--url", help="URL to analyze")
    parser.add_argument("--image", help="Optional screenshot path")
    parser.add_argument("--no-gui", action="store_true", help="Run without opening the desktop UI")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.no_gui and not args.url:
        app = PhishingApp()
        app.mainloop()
        return 0

    if not args.url:
        parser.error("--url is required when using --no-gui")

    detector = PhishingDetector()
    result = detector.predict(args.url, Path(args.image) if args.image else None)

    print(f"Label: {result.label}")
    print(f"Score: {result.score:.3f}")
    print(f"URL score: {result.url_score:.3f}")
    print(f"Visual score: {result.visual_score:.3f}")
    print("Reasons:")
    for reason in result.reasons:
        print(f"- {reason}")
    print("Metrics:")
    for key, value in result.metrics.items():
        print(f"- {key}: {value:.3f}")
    return 0

