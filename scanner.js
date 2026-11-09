
document.addEventListener("DOMContentLoaded", function () {

    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");
    const scanButton = document.getElementById("scanButton");
    const scanLoading = document.getElementById("scanLoading");
    const scanResult = document.getElementById("scanResult");

    const resultIcon = document.getElementById("resultIcon");
    const resultTitle = document.getElementById("resultTitle");
    const resultMessage = document.getElementById("resultMessage");
    const riskLevel = document.getElementById("riskLevel");
    const reportList = document.getElementById("reportList");

    if (!scanForm || !urlInput) return;

    // Local reference list. Not a live verification database.
    const trustedReferences = {
        google: ["google.com"],
        microsoft: ["microsoft.com"],
        apple: ["apple.com"],
        paypal: ["paypal.com"],
        facebook: ["facebook.com"],
        instagram: ["instagram.com"],
        amazon: ["amazon.com", "amazon.in"]
    };

    const suspiciousWords = [
        "verify", "login", "update", "password",
        "banking", "account", "reward", "claim",
        "free", "secure", "confirm", "wallet",
        "otp", "signin", "payment"
    ];

    function addReport(reports, heading, detail) {
        reports.push(heading + ": " + detail);
    }

    function addRisk(state, points, heading, detail) {
        state.score += points;

        addReport(
            state.reports,
            heading,
            detail + " (+" + points + " risk points)"
        );
    }

    // Calculate spelling difference.
    function getSpellingDifference(original, detected) {

        const matrix = [];

        for (let i = 0; i <= detected.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= original.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= detected.length; i++) {

            for (let j = 1; j <= original.length; j++) {

                const cost =
                    detected[i - 1] === original[j - 1] ? 0 : 1;

                matrix[i][j] = Math.min(
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost
                );
            }
        }

        // Trace back to find changed positions.
        let i = detected.length;
        let j = original.length;
        const differences = [];

        while (i > 0 || j > 0) {

            if (
                i > 0 &&
                j > 0 &&
                detected[i - 1] === original[j - 1]
            ) {
                i--;
                j--;
            }

            else if (
                i > 0 &&
                j > 0 &&
                matrix[i][j] === matrix[i - 1][j - 1] + 1
            ) {

                differences.unshift({
                    position: i,
                    expected: original[j - 1],
                    found: detected[i - 1]
                });

                i--;
                j--;
            }

            else if (
                j > 0 &&
                matrix[i][j] === matrix[i][j - 1] + 1
            ) {

                differences.unshift({
                    position: i + 1,
                    expected: original[j - 1],
                    found: "(अतिरिक्त अक्षर)"
                });

                j--;
            }

            else if (i > 0) {

                differences.unshift({
                    position: i,
                    expected: "(अक्षर नाही)",
                    found: detected[i - 1]
                });

                i--;
            }
        }

        return differences;
    }

    // Detect visually similar Latin characters.
    function normalizeLookalikes(value) {

        const replacements = {
            "0": "o",
            "1": "l",
            "i": "l",
            "rn": "m"
        };

        let result = value.toLowerCase();

        result = result.replace(/0/g, replacements["0"]);
        result = result.replace(/1/g, replacements["1"]);
        result = result.replace(/i/g, replacements["i"]);
        result = result.replace(/rn/g, replacements["rn"]);

        return result;
    }

    // Compare host with the limited local reference list.
    
function getReferenceMatch(hostname) {

    const host = hostname.toLowerCase();

    for (const brand in trustedReferences) {

        for (const domain of trustedReferences[brand]) {

            if (
                host === domain ||
                host.endsWith("." + domain)
            ) {
                return {
                    brand: brand,
                    domain: domain,
                    exact: true
                };
            }

            const referenceName = domain.split(".")[0];

            const labels = host.split(".");

            for (const label of labels) {

                const subParts = label.split("-");

                for (const part of subParts) {

                    if (
                        part === referenceName ||
                        part.length < 4
                    ) {
                        continue;
                    }

                    const normalizedPart =
                        normalizeLookalikes(part);

                    const normalizedReference =
                        normalizeLookalikes(referenceName);

                    const differences =
                        getSpellingDifference(
                            referenceName,
                            part
                        );

                    const visuallySimilar =
                        normalizedPart === normalizedReference;

                    if (
                        visuallySimilar ||
                        (
                            differences.length > 0 &&
                            differences.length <= 2 &&
                            Math.abs(
                                part.length - referenceName.length
                            ) <= 1
                        )
                    ) {
                        return {
                            brand: brand,
                            domain: domain,
                            exact: false,
                            suspiciousPart: part,
                            differences: differences,
                            visuallySimilar: visuallySimilar
                        };
                    }
                }
            }
        }
    }

    return null;
}

    function analyseURL(value) {

        const state = {
            score: 0,
            reports: [],
            verdict: "",
            message: "",
            icon: "🔍"
        };

        let parsedURL;

        try {
            parsedURL = new URL(value);
        } catch {

            state.score = 100;
            state.verdict = "INVALID URL";
            state.message =
                "लिंक योग्य स्वरूपात नाही. ती उघडू नका.";
            state.icon = "⚠️";

            addReport(
                state.reports,
                "URL FORMAT",
                "लिंकचे स्वरूप चुकीचे आहे."
            );

            return state;
        }

        if (!["http:", "https:"].includes(parsedURL.protocol)) {

            state.score = 100;
            state.verdict = "UNSUPPORTED URL";
            state.message = "ही लिंक उघडू नका.";
            state.icon = "⚠️";

            addReport(
                state.reports,
                "PROTOCOL",
                "असमर्थित URL प्रकार आढळला."
            );

            return state;
        }

        const host = parsedURL.hostname.toLowerCase();
        const parts = host.split(".");

        // URL structure
        addReport(state.reports, "MAIN DOMAIN", host);

        addReport(
            state.reports,
            "SUBDOMAIN",
            parts.length > 2
                ? parts.slice(0, -2).join(".")
                : "अतिरिक्त subdomain नाही."
        );

        addReport(
            state.reports,
            "PROTOCOL",
            parsedURL.protocol.toUpperCase()
        );

        addReport(
            state.reports,
            "PATH",
            parsedURL.pathname || "/"
        );

        if (parsedURL.search) {
            addReport(
                state.reports,
                "QUERY PARAMETERS",
                [...parsedURL.searchParams.keys()].join(", ") ||
                "Parameters आढळले."
            );
        } else {
            addReport(
                state.reports,
                "QUERY PARAMETERS",
                "Parameters नाहीत."
            );
        }

        // HTTPS
        if (parsedURL.protocol === "http:") {

            addRisk(
                state,
                15,
                "ENCRYPTION",
                "HTTPS ऐवजी HTTP वापरले आहे."
            );

        } else {

            addReport(
                state.reports,
                "ENCRYPTION",
                "HTTPS वापरले आहे; मात्र सुरक्षिततेची हमी नाही."
            );
        }

        // Credentials
        if (parsedURL.username || parsedURL.password) {

            addRisk(
                state,
                35,
                "HIDDEN CREDENTIALS",
                "URL मध्ये username किंवा password field आहे."
            );
        }

        // Punycode
        if (host.includes("xn--")) {

            addRisk(
                state,
                25,
                "PUNYCODE",
                "International domain encoding आढळले."
            );
        }

        // IP address
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {

            addRisk(
                state,
                25,
                "IP ADDRESS",
                "Domain name ऐवजी IP address वापरला आहे."
            );
        }

        // Too many domain parts
        if (parts.length > 4) {

            addRisk(
                state,
                15,
                "DOMAIN STRUCTURE",
                "Domain चे भाग खूप जास्त आहेत."
            );
        }

        // Port
        if (
            parsedURL.port &&
            !["80", "443"].includes(parsedURL.port)
        ) {

            addRisk(
                state,
                10,
                "PORT CHECK",
                "अनोळखी port आढळला: " + parsedURL.port
            );
        }

        // Suspicious words
        const lowerURL = value.toLowerCase();

        const foundWords = suspiciousWords.filter(function (word) {
            return lowerURL.includes(word);
        });

        if (foundWords.length > 0) {

            addRisk(
                state,
                Math.min(foundWords.length * 5, 25),
                "SUSPICIOUS WORDS",
                foundWords.join(", ")
            );

        } else {

            addReport(
                state.reports,
                "SUSPICIOUS WORDS",
                "निवडलेल्या संशयास्पद शब्दांची जुळणी नाही."
            );
        }

        // Spelling investigation
        const reference = getReferenceMatch(host);

        if (reference && reference.exact) {

            addReport(
                state.reports,
                "REFERENCE DOMAIN",
                reference.domain +
                " या स्थानिक reference domain शी जुळतो. Live verification नाही."
            );

        } else if (reference && !reference.exact) {

            addRisk(
                state,
                30,
                "POSSIBLE SPELLING MISTAKE",
                "'" + reference.suspiciousPart +
                "' हा भाग '" + reference.brand +
                "' या नावासारखा दिसतो."
            );

            addReport(
                state.reports,
                "REFERENCE DOMAIN",
                reference.domain
            );

            addReport(
                state.reports,
                "DETECTED DOMAIN PART",
                reference.suspiciousPart
            );

            if (reference.visuallySimilar) {

                addReport(
                    state.reports,
                    "VISUAL SIMILARITY",
                    "काही अक्षरे दिसायला सारखी असू शकतात."
                );
            }

            reference.differences.forEach(function (difference) {

                addReport(
                    state.reports,
                    "LETTER DIFFERENCE",
                    "स्थान " + difference.position +
                    ": अपेक्षित '" + difference.expected +
                    "', आढळले '" + difference.found + "'."
                );

            });

        } else {

            addReport(
                state.reports,
                "SPELLING INVESTIGATION",
                "स्थानिक reference list मध्ये जुळणारा domain आढळला नाही. त्यामुळे spelling योग्य असल्याची खात्री होत नाही."
            );
        }

        // Hyphen
        if (host.includes("-")) {

            addRisk(
                state,
                5,
                "DOMAIN SYMBOLS",
                "Domain मध्ये hyphen आहे."
            );
        }

        // @ symbol
        if (value.includes("@")) {

            addRisk(
                state,
                20,
                "AT SYMBOL",
                "URL मध्ये @ चिन्ह आढळले."
            );
        }

        // Limitations
        addReport(
            state.reports,
            "NOT CHECKED",
            "Live website reputation, ownership, redirects, website content आणि malware तपासलेले नाहीत."
        );

        state.score = Math.min(state.score, 100);

        // Final verdict
        if (state.score >= 50) {

            state.verdict = "DO NOT OPEN";
            state.message =
                "गंभीर संशयास्पद संकेत आढळले. ही लिंक उघडू नका.";
            state.icon = "🚨";

        } else if (state.score >= 20) {

            state.verdict = "VERIFY FIRST";
            state.message =
                "संशयास्पद संकेत आढळले. अधिकृत स्रोतावरून खात्री होईपर्यंत लिंक उघडू नका.";
            state.icon = "⚠️";

        } else {

            state.verdict = "NO MAJOR WARNING SIGNALS";
            state.message =
                "मोठे warning signals आढळले नाहीत. तरीही सुरक्षिततेची हमी नाही. अधिकृत वेबसाइटचा पत्ता स्वतः टाइप करा.";
            state.icon = "🔍";
        }

        return state;
    }

    function showResult(state) {

        if (scanLoading) {
            scanLoading.hidden = true;
        }

        if (scanResult) {
            scanResult.hidden = false;
        }

        if (resultIcon) {
            resultIcon.textContent = state.icon;
        }

        if (resultTitle) {
            resultTitle.textContent = state.verdict;
        }

        if (resultMessage) {
            resultMessage.textContent = state.message;
        }

        if (riskLevel) {
            riskLevel.textContent =
                "रिस्क स्कोअर: " + state.score + " / 100";
        }

        if (reportList) {

            reportList.replaceChildren();

            state.reports.forEach(function (report) {

                const item = document.createElement("li");
                item.textContent = report;

                reportList.appendChild(item);
            });

            const finalItem = document.createElement("li");

            finalItem.textContent =
                "SANJAY'S FINAL ADVICE: " + state.verdict;

            reportList.appendChild(finalItem);
        }

        if (scanButton) {
            scanButton.disabled = false;
        }
    }

    scanForm.addEventListener("submit", function (event) {

        event.preventDefault();

        const value = urlInput.value.trim();

        if (!value) {
            alert("कृपया आधी लिंक टाका.");
            return;
        }

        if (scanButton) {
            scanButton.disabled = true;
        }

        if (scanResult) {
            scanResult.hidden = true;
        }

        if (scanLoading) {
            scanLoading.hidden = false;
        }

        setTimeout(function () {

            const result = analyseURL(value);

            showResult(result);

        }, 700);

    });

});
