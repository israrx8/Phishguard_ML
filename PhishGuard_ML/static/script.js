const form = document.getElementById("scan-form");
const input = document.getElementById("url");
const button = document.getElementById("scan-button");
const result = document.getElementById("result");
const statusBox = document.getElementById("status");

const resultLabel = document.getElementById("result-label");
const resultMessage = document.getElementById("result-message");
const scoreEl = document.getElementById("score");
const confidenceEl = document.getElementById("confidence");
const scannedUrlEl = document.getElementById("scanned-url");
const signalsEl = document.getElementById("signals");

function setLoading(loading) {
    button.disabled = loading;
    button.querySelector("span").textContent = loading ? "Scanning..." : "Check URL";
}

function showError(message) {
    statusBox.textContent = message;
    statusBox.classList.remove("hidden");
    result.classList.add("hidden");
}

function clearError() {
    statusBox.classList.add("hidden");
    statusBox.textContent = "";
}

function renderSignals(features) {
    signalsEl.innerHTML = "";

    const entries = Object.entries(features);

    for (const [name, value] of entries) {
        const item = document.createElement("div");
        item.className = "signal";

        const triggered = Number(value) > 0;

        item.innerHTML = `
            <div class="signal-top">
                <span class="signal-name">${escapeHtml(name)}</span>
                <span class="signal-value">${escapeHtml(value)}</span>
            </div>
            <div class="signal-state">
                ${triggered ? "Signal present" : "No signal"}
            </div>
        `;

        signalsEl.appendChild(item);
    }
}

function applyTheme(label) {
    document.body.classList.remove("safe", "suspicious", "risky");

    const className = label.toLowerCase();
    document.body.classList.add(className);
}

function renderResult(data) {
    applyTheme(data.label);

    resultLabel.textContent = data.label;
    resultMessage.textContent = data.message;
    scoreEl.textContent = data.score;
    confidenceEl.textContent = `Model confidence: ${data.confidence}%`;
    scannedUrlEl.textContent = data.url;

    renderSignals(data.features);
    result.classList.remove("hidden");
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    clearError();

    const url = input.value.trim();

    if (!url) {
        showError("Please enter a URL.");
        return;
    }

    setLoading(true);

    try {
        const response = await fetch("/api/check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "The URL could not be scanned.");
        }

        renderResult(data);
        result.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
        showError(error.message || "Something went wrong.");
    } finally {
        setLoading(false);
    }
});
