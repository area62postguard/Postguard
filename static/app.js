const names = {
    dashboard: "PostGuard Intelligence Centre",
    scanner: "AI Post Scanner",
    alerts: "Alert Queue",
    cases: "Case Management",
    people: "Principals",
    monitoring: "Authorised Monitoring",
    audit: "Audit Log"
};

let currentAlertId = null;


// ============================================================
// NAVIGATION
// ============================================================

function show(id, el) {
    document.querySelectorAll(".page").forEach(x => {
        x.classList.remove("active");
    });

    const page = document.getElementById(id);

    if (page) {
        page.classList.add("active");
    }

    document.querySelectorAll(".nav a").forEach(x => {
        x.classList.remove("active");
    });

    if (el) {
        el.classList.add("active");
    }

    const crumb = document.getElementById("crumb");

    if (crumb) {
        crumb.textContent = names[id] || "PostGuard";
    }

    if (id === "audit") {
        loadAudit();
    }
}


// ============================================================
// IMAGE UPLOAD
// ============================================================

const image = document.getElementById("image");
const preview = document.getElementById("preview");
const drop = document.getElementById("drop");
const dropText = document.getElementById("dropText");

if (drop && image) {
    drop.onclick = () => image.click();
}

if (image) {
    image.onchange = () => {
        if (image.files && image.files[0]) {
            if (preview) {
                preview.src =
                    URL.createObjectURL(image.files[0]);

                preview.style.display = "block";
            }

            if (dropText) {
                dropText.style.display = "none";
            }
        }
    };
}


// ============================================================
// POST SCANNER
// ============================================================

async function scan() {
    const captionBox =
        document.getElementById("caption");

    const principalBox =
        document.getElementById("principal");

    const scoreBox =
        document.getElementById("score");

    const riskBox =
        document.getElementById("risk");

    const summaryBox =
        document.getElementById("summary");

    const findingsBox =
        document.getElementById("findings");

    const fd = new FormData();

    fd.append(
        "caption",
        captionBox ? captionBox.value : ""
    );

    fd.append(
        "principal_id",
        principalBox ? principalBox.value : ""
    );

    if (image && image.files && image.files[0]) {
        fd.append(
            "image",
            image.files[0]
        );
    }

    try {
        const r = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "X-CSRFToken":
                    window.POSTGUARD_CSRF
            },
            body: fd
        });

        const d = await r.json();

        if (!r.ok) {
            return alert(
                d.error || "Scan failed."
            );
        }

        if (scoreBox) {
            scoreBox.textContent = d.score;
        }

        if (riskBox) {
            riskBox.textContent =
                d.risk + " RISK";
        }

        if (summaryBox) {
            summaryBox.textContent =
                d.risk === "LOW"
                    ? "No major signals detected."
                    : "Review every finding before publication.";
        }

        if (findingsBox) {
            findingsBox.innerHTML =
                (d.findings || []).map(f => `
                    <div class="finding">
                        <b>
                            ${escapeHtml(f.severity)}
                            ·
                            ${escapeHtml(f.category)}
                        </b>

                        <span class="muted">
                            ${escapeHtml(f.detail)}
                        </span>

                        <div class="recommend">
                            <b>Recommended action</b>
                            ${escapeHtml(f.recommendation)}
                        </div>
                    </div>
                `).join("");
        }

        // Keep result visible for 10 seconds.
        setTimeout(() => {
            location.reload();
        }, 10000);

    } catch (error) {
        console.error(error);

        alert(
            "PostGuard could not complete the scan."
        );
    }
}


// ============================================================
// ALERT DETAILS
// ============================================================

function openAlert(button) {
    if (!button) {
        return;
    }

    currentAlertId = button.dataset.id;

    const setText = (
        id,
        value,
        fallback = "Not recorded"
    ) => {
        const element =
            document.getElementById(id);

        if (!element) {
            return;
        }

        element.textContent =
            value !== undefined &&
            value !== null &&
            value !== ""
                ? value
                : fallback;
    };

    setText(
        "alertTitle",
        button.dataset.category,
        "Alert details"
    );

    setText(
        "alertSeverity",
        button.dataset.severity,
        "Unknown"
    );

    setText(
        "alertPrincipal",
        button.dataset.principal,
        "Unassigned"
    );

    setText(
        "alertStatus",
        button.dataset.status,
        "Unknown"
    );

    setText(
        "alertCreated",
        button.dataset.created,
        "Unknown"
    );

    setText(
        "alertDetail",
        button.dataset.detail,
        "No detail recorded."
    );

    setText(
        "alertRecommendation",
        button.dataset.recommendation,
        "No recommendation recorded."
    );

    setText(
        "alertCaption",
        button.dataset.caption,
        "Not recorded."
    );

    setText(
        "alertCheckId",
        button.dataset.checkId,
        "Not recorded"
    );

    const scoreElement =
        document.getElementById(
            "alertScore"
        );

    if (scoreElement) {
        scoreElement.textContent =
            button.dataset.score
                ? `${button.dataset.score}/100`
                : "Not recorded";
    }

    const closeButton =
        document.getElementById(
            "alertCloseButton"
        );

    if (closeButton) {
        closeButton.style.display =
            button.dataset.status === "Closed"
                ? "none"
                : "inline-block";
    }

    const caseButton =
        document.getElementById(
            "alertCaseButton"
        );

    if (caseButton) {
        if (button.dataset.status === "Open") {
            caseButton.style.display =
                "inline-block";

            caseButton.disabled = false;

            caseButton.textContent =
                "Create Case";
        } else {
            caseButton.style.display =
                "none";
        }
    }

    const modal =
        document.getElementById(
            "alertModal"
        );

    if (!modal) {
        alert(
            "Alert window is missing from app.html."
        );

        return;
    }

    modal.style.display = "flex";
}


// ============================================================
// CLOSE ALERT WINDOW
// ============================================================

function closeAlertModal() {
    currentAlertId = null;

    const modal =
        document.getElementById(
            "alertModal"
        );

    if (modal) {
        modal.style.display = "none";
    }
}


// ============================================================
// CLOSE ALERT
// ============================================================

async function closeCurrentAlert() {
    if (!currentAlertId) {
        return;
    }

    await closeAlert(
        currentAlertId
    );
}


async function closeAlert(id) {
    try {
        const r = await fetch(
            "/api/alerts/" +
                id +
                "/close",
            {
                method: "POST",
                headers: {
                    "X-CSRFToken":
                        window.POSTGUARD_CSRF
                }
            }
        );

        if (!r.ok) {
            return alert(
                "Could not close alert."
            );
        }

        location.reload();

    } catch (error) {
        console.error(error);

        alert(
            "Could not close alert."
        );
    }
}


// ============================================================
// CREATE CASE FROM ALERT
// ============================================================

async function createCaseFromAlert() {
    if (!currentAlertId) {
        return;
    }

    const button =
        document.getElementById(
            "alertCaseButton"
        );

    if (button) {
        button.disabled = true;

        button.textContent =
            "Creating case...";
    }

    try {
        const r = await fetch(
            "/api/alerts/" +
                currentAlertId +
                "/case",
            {
                method: "POST",
                headers: {
                    "X-CSRFToken":
                        window.POSTGUARD_CSRF
                }
            }
        );

        let d = {};

        try {
            d = await r.json();
        } catch (error) {
            console.error(error);
        }

        if (!r.ok) {
            if (button) {
                button.disabled = false;

                button.textContent =
                    "Create Case";
            }

            return alert(
                d.error ||
                "Could not create case."
            );
        }

        alert(
            "Case created successfully."
        );

        location.reload();

    } catch (error) {
        console.error(error);

        if (button) {
            button.disabled = false;

            button.textContent =
                "Create Case";
        }

        alert(
            "Could not create case."
        );
    }
}


// ============================================================
// CASES
// ============================================================

async function newCase() {
    const title =
        prompt("Case title");

    if (!title) {
        return;
    }

    try {
        const r = await fetch(
            "/api/cases",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json",

                    "X-CSRFToken":
                        window.POSTGUARD_CSRF
                },
                body: JSON.stringify({
                    title
                })
            }
        );

        if (!r.ok) {
            return alert(
                "Could not create case."
            );
        }

        location.reload();

    } catch (error) {
        console.error(error);

        alert(
            "Could not create case."
        );
    }
}


async function closeCase(id) {
    try {
        const r = await fetch(
            "/api/cases/" +
                id +
                "/close",
            {
                method: "POST",
                headers: {
                    "X-CSRFToken":
                        window.POSTGUARD_CSRF
                }
            }
        );

        if (!r.ok) {
            return alert(
                "Could not close case."
            );
        }

        location.reload();

    } catch (error) {
        console.error(error);

        alert(
            "Could not close case."
        );
    }
}


// ============================================================
// PRINCIPALS
// ============================================================

async function addPrincipal() {
    const name =
        prompt("Principal name");

    if (!name) {
        return;
    }

    const role =
        prompt(
            "Role",
            "Executive"
        ) || "Executive";

    try {
        const r = await fetch(
            "/api/principals",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json",

                    "X-CSRFToken":
                        window.POSTGUARD_CSRF
                },
                body: JSON.stringify({
                    name,
                    role
                })
            }
        );

        if (!r.ok) {
            return alert(
                "Could not add principal."
            );
        }

        location.reload();

    } catch (error) {
        console.error(error);

        alert(
            "Could not add principal."
        );
    }
}


// ============================================================
// MONITORING SOURCES
// ============================================================

async function addSource() {
    const name =
        prompt("Source name");

    if (!name) {
        return;
    }

    const kind =
        prompt(
            "Source type",
            "Authorised social source"
        ) ||
        "Authorised source";

    try {
        const r = await fetch(
            "/api/sources",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json",

                    "X-CSRFToken":
                        window.POSTGUARD_CSRF
                },
                body: JSON.stringify({
                    name,
                    kind
                })
            }
        );

        if (!r.ok) {
            return alert(
                "Could not add source."
            );
        }

        location.reload();

    } catch (error) {
        console.error(error);

        alert(
            "Could not add source."
        );
    }
}


// ============================================================
// AUDIT LOG
// ============================================================

async function loadAudit() {
    const auditBox =
        document.getElementById(
            "auditBox"
        );

    if (!auditBox) {
        return;
    }

    try {
        const r =
            await fetch("/api/audit");

        const d =
            await r.json();

        if (!r.ok) {
            auditBox.textContent =
                "Could not load audit log.";

            return;
        }

        auditBox.textContent =
            d.map(x =>
                `${x.created_at} | ${x.email} | ${x.action} | ${x.detail}`
            ).join("\n") ||
            "No events.";

    } catch (error) {
        console.error(error);

        auditBox.textContent =
            "Could not load audit log.";
    }
}


// ============================================================
// PRINCIPAL SECURE PUBLISH CENTRE
// ============================================================

async function publishPrincipalPost(
    principalId
) {
    const platform =
        document.getElementById(
            "publishPlatform"
        );

    const captionBox =
        document.getElementById(
            "publishCaption"
        );

    const imageBox =
        document.getElementById(
            "publishImage"
        );

    const result =
        document.getElementById(
            "publishResult"
        );

    if (
        !platform ||
        !captionBox ||
        !imageBox ||
        !result
    ) {
        alert(
            "Publish Centre is not configured correctly."
        );

        return;
    }

    const fd =
        new FormData();

    fd.append(
        "platform",
        platform.value
    );

    fd.append(
        "caption",
        captionBox.value
    );

    if (
        imageBox.files &&
        imageBox.files[0]
    ) {
        fd.append(
            "image",
            imageBox.files[0]
        );
    }

    result.style.display =
        "block";

    result.textContent =
        "Running PostGuard security check...";

    try {
        const r = await fetch(
            `/api/principals/${principalId}/publish`,
            {
                method: "POST",
                headers: {
                    "X-CSRFToken":
                        window.POSTGUARD_CSRF
                },
                body: fd
            }
        );

        let d = {};

        try {
            d = await r.json();
        } catch (error) {
            console.error(error);
        }

        if (d.blocked) {
            result.textContent =
                `Publishing blocked · ` +
                `${d.risk} · ` +
                `${d.score}/100 · ` +
                `${d.error}`;

            return;
        }

        if (d.connection_required) {
            result.textContent =
                `Security check passed · ` +
                `${d.risk} · ` +
                `${d.score}/100 · ` +
                `${d.message}`;

            return;
        }

        if (!r.ok) {
            result.textContent =
                d.error ||
                "Could not process the post.";

            return;
        }

        result.textContent =
            d.message ||
            "Post processed.";

    } catch (error) {
        console.error(error);

        result.textContent =
            "Publishing request failed.";
    }
}


// ============================================================
// HTML ESCAPING
// ============================================================

function escapeHtml(value) {
    if (
        value === undefined ||
        value === null
    ) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


// ============================================================
// KEYBOARD CONTROLS
// ============================================================

document.addEventListener(
    "keydown",
    event => {
        if (event.key === "Escape") {
            closeAlertModal();
        }
    }
);
