from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .predictor import PhishingDetector


class PhishingApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Safe URL Checker")
        self.geometry("980x640")
        self.minsize(900, 600)
        self.configure(bg="#0b1020")

        self.detector = PhishingDetector()
        self.selected_image: str | None = None

        self._build_style()
        self._build_ui()

    def _build_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Root.TFrame", background="#0b1020")
        style.configure("Hero.TFrame", background="#111827")
        style.configure("Card.TFrame", background="#151b2f")
        style.configure("Title.TLabel", background="#111827", foreground="#f8fafc", font=("Segoe UI", 24, "bold"))
        style.configure("Subtitle.TLabel", background="#111827", foreground="#cbd5e1", font=("Segoe UI", 11))
        style.configure("Body.TLabel", background="#151b2f", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=10, background="#7c3aed", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#8b5cf6")])
        style.configure("TEntry", padding=10, fieldbackground="#0f172a", foreground="#f8fafc")
        style.configure("Verdict.TLabel", background="#151b2f", foreground="#ffffff", font=("Segoe UI", 30, "bold"))
        style.configure("Score.TLabel", background="#151b2f", foreground="#cbd5e1", font=("Segoe UI", 11))

    def _build_ui(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame", padding=20)
        root.pack(fill="both", expand=True)

        hero = ttk.Frame(root, style="Hero.TFrame", padding=22)
        hero.pack(fill="x")

        header = ttk.Label(hero, text="Safe URL Checker", style="Title.TLabel")
        header.pack(anchor="w")
        sub = ttk.Label(
            hero,
            text="Type a URL and get a simple Safe or Unsafe verdict.",
            style="Subtitle.TLabel",
        )
        sub.pack(anchor="w", pady=(6, 0))

        panel = ttk.Frame(root, style="Card.TFrame", padding=20)
        panel.pack(fill="both", expand=True, pady=(18, 0))

        ttk.Label(panel, text="URL", style="Body.TLabel").grid(row=0, column=0, sticky="w")
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(panel, textvariable=self.url_var, width=100)
        url_entry.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(6, 16))
        url_entry.focus_set()

        ttk.Button(panel, text="Add Screenshot", style="Accent.TButton", command=self._choose_image).grid(
            row=2, column=0, sticky="w"
        )
        self.image_label = ttk.Label(panel, text="No screenshot selected", style="Body.TLabel")
        self.image_label.grid(row=2, column=1, sticky="w", padx=(12, 0))

        ttk.Button(panel, text="Check URL", style="Accent.TButton", command=self._analyze).grid(
            row=2, column=2, sticky="e"
        )

        result_card = ttk.Frame(panel, style="Card.TFrame", padding=22)
        result_card.grid(row=3, column=0, columnspan=3, sticky="nsew", pady=(24, 0))

        self.result_label = ttk.Label(result_card, text="READY", style="Verdict.TLabel")
        self.result_label.pack(anchor="w")

        self.score_label = ttk.Label(result_card, text="Enter a URL to check", style="Score.TLabel")
        self.score_label.pack(anchor="w", pady=(8, 0))

        self.metrics_label = ttk.Label(result_card, text="", style="Score.TLabel")
        self.metrics_label.pack(anchor="w", pady=(8, 0))

        self.text = ttk.Label(
            result_card,
            text="Safe URLs will appear in green. Unsafe URLs will appear in red.",
            style="Score.TLabel",
        )
        self.text.pack(anchor="w", pady=(18, 0))

        panel.columnconfigure(0, weight=1)
        panel.columnconfigure(1, weight=1)
        panel.columnconfigure(2, weight=0)
        panel.rowconfigure(3, weight=1)

    def _choose_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select a screenshot",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All files", "*.*")],
        )
        if path:
            self.selected_image = path
            self.image_label.config(text=path)

    def _analyze(self) -> None:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "Enter a URL before running analysis.")
            return

        result = self.detector.predict(url, self.selected_image)
        is_safe = result.label == "Legitimate"
        verdict = "SAFE" if is_safe else "UNSAFE"
        verdict_color = "#22c55e" if is_safe else "#ef4444"
        self.result_label.config(text=verdict, foreground=verdict_color)
        self.score_label.config(text=f"Confidence: {result.score:.0%}")
        self.metrics_label.config(text="")
        self.text.config(
            text="This URL looks safe to open." if is_safe else "This URL looks unsafe. Avoid opening it."
        )
