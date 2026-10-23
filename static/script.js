
const $ = (selector) => document.querySelector(selector);

const validateForm = $("#validate-form");
const urlInput = $("#url");
const validateButton = $("#validate-button");

const results = $("#results");
const resultTitle = $("#result-title");
const resultMessage = $("#result-message");
const resultDetails = $("#result-details");

const preflightButton = $("#preflight-button");
const preflightResults = $("#preflight-results");
const preflightTitle = $("#preflight-title");
const preflightMessage = $("#preflight-message");
const preflightDetails = $("#preflight-details");

const headersInput = $("#headers-input");
const sampleHeadersButton = $("#sample-headers-button");
const clearHeadersButton = $("#clear-headers-button");
const analyzeHeadersButton = $("#analyze-headers-button");
const headerResults = $("#header-results");
const headerResultTitle = $("#header-result-title");
const headerResultMessage = $("#header-result-message");
const headerSummary = $("#header-summary");
const headerFindings = $("#header-findings");
const headerScorePanel = $("#header-score-panel");
const downloadReportButton = $("#download-report-button");

let requestInProgress = false;
let latestHeaderReport = null;

const sampleHeaders = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin"
};

function setBusy(busy) {
    requestInProgress = busy;
    validateButton.disabled = busy;
    preflightButton.disabled = busy;
    analyzeHeadersButton.disabled = busy;
    sampleHeadersButton.disabled = busy;
    clearHeadersButton.disabled = busy;
}

async function postJson(endpoint, payload) {
    const response = await fetch(endpoint, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
    });

    let data;
    try {
        data = await response.json();
    } catch {
        throw new Error("The server returned an unreadable response.");
    }

    if (!response.ok) {
        throw new Error(data.error || "The request could not be processed.");
    }
    return data;
}

function showError(section, title, message, error) {
    section.hidden = false;
    section.className = "results error";
    title.textContent = "Unable to complete the request";
    message.textContent = error;
}

validateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (requestInProgress) return;

    setBusy(true);
    validateButton.textContent = "Validating…";
    results.hidden = true;

    try {
        const data = await postJson("/api/validate", {url: urlInput.value});
        results.hidden = false;
        results.className = data.valid ? "results success" : "results error";
        resultTitle.textContent = data.valid ? "URL format accepted" : "Validation failed";
        resultMessage.textContent = data.valid
            ? data.message
            : data.error || "The URL did not pass validation.";

        resultDetails.hidden = !data.valid;
        if (data.valid) {
            $("#result-hostname").textContent = data.hostname;
            $("#result-scheme").textContent = data.scheme.toUpperCase();
            $("#result-https").textContent = data.https ? "Yes" : "No";
        }
    } catch (error) {
        showError(results, resultTitle, resultMessage,
            error.message || "Could not reach the local validation endpoint.");
        resultDetails.hidden = true;
    } finally {
        validateButton.textContent = "Validate URL";
        setBusy(false);
    }
});

preflightButton.addEventListener("click", async () => {
    if (requestInProgress) return;

    if (!urlInput.value.trim()) {
        showError(preflightResults, preflightTitle, preflightMessage,
            "Enter a URL in the Website URL field first.");
        preflightDetails.hidden = true;
        urlInput.focus();
        return;
    }

    setBusy(true);
    preflightButton.textContent = "Checking…";
    preflightResults.hidden = true;

    try {
        const data = await postJson("/api/preflight", {url: urlInput.value});
        const passed = data.safe === true;

        preflightResults.hidden = false;
        preflightResults.className = passed ? "results success" : "results error";
        preflightTitle.textContent = passed ? "Preflight checks passed" : "Preflight rejected";
        preflightMessage.textContent = data.message || data.error || "Preflight completed.";
        preflightDetails.hidden = !passed;

        if (passed) {
            $("#preflight-hostname").textContent = data.hostname || "—";
            $("#preflight-scheme").textContent = (data.scheme || "—").toUpperCase();
            $("#preflight-https").textContent = data.https ? "Yes" : "No";
            $("#preflight-addresses").textContent =
                Array.isArray(data.addresses) ? data.addresses.join(", ") : "None returned";
        }
    } catch (error) {
        showError(preflightResults, preflightTitle, preflightMessage,
            error.message || "Could not reach the local preflight endpoint.");
        preflightDetails.hidden = true;
    } finally {
        preflightButton.textContent = "Run Preflight";
        setBusy(false);
    }
});

sampleHeadersButton.addEventListener("click", () => {
    headersInput.value = JSON.stringify(sampleHeaders, null, 2);
    headersInput.focus();
});

clearHeadersButton.addEventListener("click", () => {
    headersInput.value = "";
    headerResults.hidden = true;
    headerFindings.replaceChildren();
    latestHeaderReport = null;
    downloadReportButton.hidden = true;
    headerScorePanel.hidden = true;
    headerSummary.hidden = true;
    headersInput.focus();
});

function createFindingCard(finding) {
    const card = document.createElement("article");
    card.className = "finding-card";

    const top = document.createElement("div");
    top.className = "finding-top";

    const name = document.createElement("h4");
    name.textContent = finding.header;

    const badge = document.createElement("span");
    badge.className = `finding-status ${finding.status}`;
    badge.textContent = finding.status;
    top.append(name, badge);

    const purpose = document.createElement("p");
    purpose.className = "finding-purpose";
    purpose.textContent = finding.purpose;

    const value = document.createElement("p");
    value.className = "finding-value";
    const label = document.createElement("strong");
    label.textContent = "Supplied value: ";
    const code = document.createElement("code");
    code.textContent = finding.value ?? "Not supplied";
    value.append(label, code);

    const recommendation = document.createElement("p");
    recommendation.className = "finding-recommendation";
    recommendation.textContent = finding.recommendation;

    card.append(top, purpose, value, recommendation);
    return card;
}

function renderHeaderReport(data) {
    headerResults.hidden = false;
    headerResults.className = "results success";
    headerResultTitle.textContent = "Security header report";
    headerResultMessage.textContent = data.message;

    const counts = data.counts;
    $("#header-count-present").textContent = counts.present;
    $("#header-count-missing").textContent = counts.missing;
    $("#header-count-review").textContent = counts.review;
    $("#header-count-total").textContent = counts.total;
    headerSummary.hidden = false;

    $("#header-score-value").textContent = data.score;
    $("#header-score-label").textContent = data.score_label;
    $("#header-score-method").textContent = data.scoring_method;
    headerScorePanel.hidden = false;

    headerFindings.replaceChildren();
    for (const finding of data.findings) {
        headerFindings.appendChild(createFindingCard(finding));
    }

    latestHeaderReport = {
        generated_at: new Date().toISOString(),
        report_type: "SecureScan offline security header analysis",
        score: data.score,
        score_label: data.score_label,
        scoring_method: data.scoring_method,
        counts: data.counts,
        findings: data.findings,
        message: data.message
    };

    downloadReportButton.hidden = false;
}

analyzeHeadersButton.addEventListener("click", async () => {
    if (requestInProgress) return;

    let headers;
    try {
        headers = JSON.parse(headersInput.value);
    } catch {
        showError(headerResults, headerResultTitle, headerResultMessage,
            "Invalid JSON. Check quotation marks, commas, and braces.");
        headerSummary.hidden = true;
        headerScorePanel.hidden = true;
        headerFindings.replaceChildren();
        downloadReportButton.hidden = true;
        return;
    }

    if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
        showError(headerResults, headerResultTitle, headerResultMessage,
            "Enter a JSON object containing header names and string values.");
        headerSummary.hidden = true;
        headerScorePanel.hidden = true;
        headerFindings.replaceChildren();
        downloadReportButton.hidden = true;
        return;
    }

    setBusy(true);
    analyzeHeadersButton.textContent = "Analyzing…";
    headerResults.hidden = true;

    try {
        const data = await postJson("/api/analyze-headers", {headers});
        if (data.success !== true) {
            throw new Error(data.error || "Header analysis failed.");
        }
        renderHeaderReport(data);
    } catch (error) {
        showError(headerResults, headerResultTitle, headerResultMessage,
            error.message || "Could not reach the local header analyzer.");
        headerSummary.hidden = true;
        headerScorePanel.hidden = true;
        headerFindings.replaceChildren();
        downloadReportButton.hidden = true;
    } finally {
        analyzeHeadersButton.textContent = "Analyze Headers";
        setBusy(false);
    }
});

downloadReportButton.addEventListener("click", () => {
    if (!latestHeaderReport) return;

    const blob = new Blob(
        [JSON.stringify(latestHeaderReport, null, 2)],
        {type: "application/json"}
    );
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = objectUrl;
    link.download = "securescan-header-report.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
});
