const urlInput = document.getElementById("url");
const screenshotInput = document.getElementById("screenshot");
const checkBtn = document.getElementById("checkBtn");
const verdict = document.getElementById("verdict");
const confidence = document.getElementById("confidence");
const score = document.getElementById("score");
const reasons = document.getElementById("reasons");

function setLoading(loading) {
  checkBtn.disabled = loading;
  checkBtn.textContent = loading ? "Checking..." : "Check URL";
}

function setResult(data) {
  verdict.className = "verdict " + (data.verdict === "SAFE" ? "safe" : "unsafe");
  verdict.textContent = data.verdict;
  confidence.textContent = `Confidence: ${data.confidence}`;
  score.textContent = `Model score: ${data.score}`;
  reasons.innerHTML = "";

  const items = Array.isArray(data.reasons) && data.reasons.length ? data.reasons : ["No strong phishing indicators were detected."];
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    reasons.appendChild(li);
  }
}

async function checkUrl() {
  const url = urlInput.value.trim();
  if (!url) {
    verdict.className = "verdict unsafe";
    verdict.textContent = "MISSING";
    confidence.textContent = "Please enter a URL first.";
    score.textContent = "";
    reasons.innerHTML = "<li>URL input is required.</li>";
    return;
  }

  setLoading(true);
  try {
    let imageData = "";
    const file = screenshotInput.files && screenshotInput.files[0];
    if (file) {
      imageData = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || ""));
        reader.onerror = () => reject(new Error("Could not read screenshot"));
        reader.readAsDataURL(file);
      });
    }

    const response = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, image_data: imageData }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Failed to check URL");
    }
    setResult(data);
  } catch (error) {
    verdict.className = "verdict unsafe";
    verdict.textContent = "ERROR";
    confidence.textContent = error.message;
    score.textContent = "";
    reasons.innerHTML = "<li>Try again after refreshing the page.</li>";
  } finally {
    setLoading(false);
  }
}

checkBtn.addEventListener("click", checkUrl);
urlInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    checkUrl();
  }
});
