# AI-Powered Phishing Detection

This project detects phishing attempts using:

- URL lexical and structural features
- A machine-learning classifier trained on phishing-like URL patterns
- Optional screenshot analysis with YOLO-based visual cues

## Run

```bash
python -m pip install -r requirements.txt
python app.py
```

You can also start it with:

```bash
python main.py
```

## What it does

- Scores suspicious URL patterns such as IP-based hosts, punycode, excessive subdomains, and credential-like paths
- Uses a trained classifier to estimate phishing probability
- Uses screenshot analysis when an image is provided
- Generates explanations for the final decision

## Notes

- The model is trained automatically the first time you run it if no saved model exists.
- The browser app runs on `http://127.0.0.1:8000`.
- The browser UI is built with `HTML`, `CSS`, and `JavaScript`.
- You can upload a screenshot to activate the YOLO-based visual check.
- The first training run downloads the UCI phishing dataset and stores a cached copy in `artifacts/`.
- Screenshot analysis uses YOLO when the dependency and weights are available; otherwise it falls back to OpenCV-based visual heuristics.
- If you want live YOLO inference for screenshots, install `ultralytics` separately:

```bash
python -m pip install ultralytics
```
