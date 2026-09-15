
const $ = id => document.getElementById(id);

const input = $("urlInput");
const scanButton = $("scanButton");

let latestReport = null;


function value(data, keys, fallback = "—") {

    for (const key of keys) {

        if (
            data &&
            data[key] !== undefined &&
            data[key] !== null
        ) {
            return data[key];
        }
    }

    return fallback;
}


function escapeHTML(text) {

    const element = document.createElement("div");
    element.textContent = String(text);

    return element.innerHTML;
}


function riskTheme(level) {

    const themes = {

        LOW:{
            color:"#21d07a",
            soft:"#0a3523",
            border:"#155c3e",
            icon:"✓"
        },

        MEDIUM:{
            color:"#f3c744",
            soft:"#342c0d",
            border:"#66571d",
            icon:"!"
        },

        HIGH:{
            color:"#ff842b",
            soft:"#3b210e",
            border:"#73411c",
            icon:"!"
        },

        CRITICAL:{
            color:"#ff4e62",
            soft:"#3b1219",
            border:"#772735",
            icon:"!"
        }

    };

    return themes[level] || themes.MEDIUM;
}


function formatDate(value) {

    if (!value) return "—";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString();
}


function boolStatus(
    element,
    status,
    goodText,
    badText
) {

    if (status) {

        element.textContent =
            "✓ " + goodText;

        element.className =
            "status-good";

    } else {

        element.textContent =
            "✕ " + badText;

        element.className =
            "status-bad";
    }
}


function showLoading(url) {

    $("errorPanel").classList.add("hidden");
    $("report").classList.add("hidden");

    $("loadingTarget").textContent =
        "Analysing " + url;

    $("loading").classList.remove("hidden");

    scanButton.disabled = true;

    scanButton
        .querySelector("span")
        .textContent = "Analysing...";
}


function stopLoading() {

    $("loading").classList.add("hidden");

    scanButton.disabled = false;

    scanButton
        .querySelector("span")
        .textContent = "Analyse Website";
}


function showError(message) {

    $("errorText").textContent = message;

    $("errorPanel")
        .classList
        .remove("hidden");

    $("errorPanel").scrollIntoView({
        behavior:"smooth",
        block:"center"
    });
}


async function analyse() {

    const url = input.value.trim();

    if (!url) {

        showError(
            "Enter a website URL or domain to analyse."
        );

        return;
    }

    showLoading(url);

    try {

        const response = await fetch(
            "/api/scan",
            {
                method:"POST",

                headers:{
                    "Content-Type":
                        "application/json"
                },

                body:JSON.stringify({
                    url:url
                })
            }
        );


        let data;

        try {

            data = await response.json();

        }
        catch {

            throw new Error(
                "The analysis service returned an invalid response."
            );
        }


        if (!response.ok) {

            throw new Error(
                data.detail ||
                data.error ||
                "The website could not be analysed."
            );
        }


        latestReport = data;

        renderReport(data);

    }
    catch (error) {

        showError(
            error.message ||
            "The analysis could not be completed."
        );

    }
    finally {

        stopLoading();
    }
}


function renderReport(data) {

    const overall = Number(
        value(
            data,
            [
                "overall_risk_score",
                "risk_score"
            ],
            0
        )
    );


    const cnn = Number(
        value(
            data,
            [
                "cnn_phishing_score",
                "deep_learning_score"
            ],
            0
        )
    );


    const lexical = Number(
        value(
            data,
            [
                "lexical_risk_score",
                "url_risk_score"
            ],
            0
        )
    );


    const live = Number(
        value(
            data,
            [
                "live_website_risk_score",
                "live_risk_score"
            ],
            0
        )
    );


    const level = String(
        value(
            data,
            [
                "risk_level",
                "level"
            ],
            "MEDIUM"
        )
    ).toUpperCase();


    const theme =
        riskTheme(level);


    /* REPORT INFORMATION */

    $("reportTarget").textContent =
        "Submitted target: " +
        value(
            data,
            [
                "url",
                "normalized_url"
            ],
            input.value
        );


    $("reportId").textContent =
        value(
            data,
            ["report_id"]
        );


    $("scanTime").textContent =
        formatDate(
            value(
                data,
                ["scan_time"],
                null
            )
        );


    $("finalUrl").textContent =
        value(
            data,
            ["final_url"]
        );


    $("submittedUrl").textContent =
        value(
            data,
            ["url"],
            input.value
        );


    $("cnnInput").textContent =
        value(
            data,
            ["cnn_input"]
        );


    /* RISK GAUGE */

    $("riskScore").textContent =
        overall.toFixed(1);


    $("riskGauge").style.setProperty(
        "--risk",
        Math.min(
            Math.max(
                overall,
                0
            ),
            100
        ) * 3.6 + "deg"
    );


    $("riskGauge").style.setProperty(
        "--risk-color",
        theme.color
    );


    $("riskBadge").textContent =
        level + " RISK";


    $("riskBadge").style.color =
        theme.color;


    $("riskBadge").style.background =
        theme.soft;


    $("riskBadge").style.borderColor =
        theme.border;


    /* SECURITY ASSESSMENT */

    $("assessmentIcon").textContent =
        theme.icon;


    $("assessmentIcon").style.color =
        theme.color;


    $("assessmentIcon").style.background =
        theme.soft;


    $("assessmentIcon").style.borderColor =
        theme.border;


    if (level === "LOW") {

        $("assessmentTitle").textContent =
            "No strong phishing indicators detected.";

    }
    else if (level === "MEDIUM") {

        $("assessmentTitle").textContent =
            "Suspicious indicators require attention.";

    }
    else if (level === "HIGH") {

        $("assessmentTitle").textContent =
            "Multiple phishing indicators were detected.";

    }
    else {

        $("assessmentTitle").textContent =
            "Strong phishing indicators detected.";
    }


    let reasons = value(
        data,
        [
            "reasons",
            "risk_reasons"
        ],
        []
    );


    if (typeof reasons === "string") {

        reasons = [reasons];
    }


    if (!Array.isArray(reasons)) {

        reasons = [];
    }


    $("assessmentReason").textContent =
        reasons.length
        ? reasons[0]
        : "No major phishing indicators were identified by the analysis layers.";


    /* DETECTION ENGINES */

    $("cnnScore").textContent =
        cnn.toFixed(1) + "%";


    $("lexicalScore").textContent =
        lexical.toFixed(1) + "%";


    $("liveScore").textContent =
        live.toFixed(1) + "%";


    $("cnnBar").style.width =
        Math.min(
            Math.max(cnn,0),
            100
        ) + "%";


    $("lexicalBar").style.width =
        Math.min(
            Math.max(lexical,0),
            100
        ) + "%";


    $("liveBar").style.width =
        Math.min(
            Math.max(live,0),
            100
        ) + "%";


    /* DOMAIN + NETWORK */

    $("domain").textContent =
        value(
            data,
            [
                "registered_domain",
                "domain"
            ]
        );


    $("hostname").textContent =
        value(
            data,
            ["hostname"]
        );


    $("httpStatus").textContent =
        value(
            data,
            [
                "http_status",
                "status_code"
            ]
        );


    const https = Boolean(
        value(
            data,
            [
                "https",
                "uses_https"
            ],
            false
        )
    );


    boolStatus(
        $("httpsStatus"),
        https,
        "Enabled",
        "Not detected"
    );


    const tls = Boolean(
        value(
            data,
            ["tls_valid"],
            false
        )
    );


    boolStatus(
        $("tlsStatus"),
        tls,
        "Valid",
        "Not validated"
    );


    $("tlsIssuer").textContent =
        value(
            data,
            [
                "tls_issuer",
                "certificate_issuer"
            ]
        );


    $("tlsExpiry").textContent =
        value(
            data,
            ["tls_expires"]
        );


    $("redirectCount").textContent =
        value(
            data,
            [
                "redirect_count",
                "redirects"
            ],
            0
        );


    /* WEBSITE SIGNALS */

    $("forms").textContent =
        value(
            data,
            ["forms"],
            0
        );


    $("passwordFields").textContent =
        value(
            data,
            ["password_fields"],
            0
        );


    $("emailFields").textContent =
        value(
            data,
            ["email_fields"],
            0
        );


    $("iframes").textContent =
        value(
            data,
            ["iframes"],
            0
        );


    $("externalForms").textContent =
        value(
            data,
            ["external_form_actions"],
            0
        );


    const externalRatio =
        Number(
            value(
                data,
                ["external_link_ratio"],
                0
            )
        );


    $("externalRatio").textContent =
        (externalRatio * 100)
        .toFixed(1) + "%";


    const available = Boolean(
        value(
            data,
            ["website_available"],
            false
        )
    );


    $("availability").textContent =
        available
        ? "Website inspection completed"
        : "Live website inspection unavailable";


    $("availabilityDot").style.background =
        available
        ? "#21d07a"
        : "#ff4e62";


    /* EXPLAINABLE FINDINGS */

    if (!reasons.length) {

        reasons = [
            "No major phishing indicators were detected by the current analysis layers."
        ];
    }


    $("findings").innerHTML =
        reasons
        .slice(0,8)
        .map(
            reason => `

            <div class="finding">

                <div class="finding-icon">
                    ${level === "LOW" ? "✓" : "!"}
                </div>

                <div>
                    ${escapeHTML(reason)}
                </div>

            </div>

            `
        )
        .join("");


    /* RECOMMENDATION */

    $("recommendation").textContent =
        value(
            data,
            ["recommendation"],
            "Verify the exact domain before entering sensitive information."
        );


    /* TECHNICAL ANALYSIS */

    let suspicious = value(
        data,
        ["suspicious_phrases"],
        []
    );


    if (!Array.isArray(suspicious)) {

        suspicious = [];
    }


    $("suspiciousPhrases").textContent =
        suspicious.length
        ? suspicious.join(", ")
        : "None detected";


    $("liveError").textContent =
        value(
            data,
            ["live_analysis_error"],
            "None"
        ) || "None";


    /* DISPLAY REPORT */

    $("errorPanel")
        .classList
        .add("hidden");


    $("report")
        .classList
        .remove("hidden");


    $("report").scrollIntoView({
        behavior:"smooth",
        block:"start"
    });
}


/* COPY SUMMARY */

$("copyReport").addEventListener(
    "click",
    async () => {

        if (!latestReport) {
            return;
        }


        const text =
`PhishingGuard Threat Intelligence Report

Report ID: ${value(latestReport,["report_id"])}
Target: ${value(latestReport,["url"])}
Final URL: ${value(latestReport,["final_url"])}

Risk Score: ${value(latestReport,["overall_risk_score"])}/100
Risk Level: ${value(latestReport,["risk_level"])}

Deep Learning CNN: ${value(latestReport,["cnn_phishing_score"])}%
URL Intelligence: ${value(latestReport,["lexical_risk_score"])}%
Live Website Analysis: ${value(latestReport,["live_website_risk_score"])}%

Recommendation:
${value(latestReport,["recommendation"])}

PhishingGuard automated security assessment.`;

        try {

            await navigator
                .clipboard
                .writeText(text);


            const button =
                $("copyReport");


            const oldText =
                button.textContent;


            button.textContent =
                "Copied";


            setTimeout(
                () => {
                    button.textContent =
                        oldText;
                },
                1500
            );

        }
        catch {

            alert(
                "Your browser did not allow clipboard access."
            );
        }
    }
);


/* EXPORT / PRINT */

$("printReport").addEventListener(
    "click",
    () => {
        window.print();
    }
);


/* EVENTS */

scanButton.addEventListener(
    "click",
    analyse
);


input.addEventListener(
    "keydown",
    event => {

        if (event.key === "Enter") {

            analyse();
        }
    }
);
