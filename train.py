from phishing_detector.model import save_model, train_model


def main() -> int:
    bundle = train_model()
    path = save_model(bundle)
    print(f"Saved model to {path}")
    print(f"Accuracy: {bundle.metrics.get('accuracy', 0.0):.3f}")
    print(f"ROC-AUC: {bundle.metrics.get('roc_auc', 0.0):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

