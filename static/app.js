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

    document.getElementById(id).classList.add("active");

    document.querySelectorAll(".nav a").forEach(x => {
        x.classList.remove("active");
    });

    if (el) {
        el.classList.add("active");
    }

    document.getElementById("crumb").textContent = names[id];

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

drop.onclick = () => image.click();

image.onchange = () => {
    if (image.files[0]) {
        preview.src = URL.createObjectURL(image.files[0]);
        preview.style.display = "block";
        dropText.style.display = "none";
    }
};


// ============================================================
// POST SCANNER
// ============================================================

async function scan() {
    const fd = new FormData();

    fd.append("caption", caption.value);
    fd.append("principal_id", principal.value);

    if (image.files[0]) {
        fd.append("image", image.files[0]);
    }

    const r = await fetch("/api/scan", {
        method: "POST",
        headers: {
            "X-CSRFToken": window.POSTGUARD_CSRF
        },
        body: fd
    });

    const d = await r.json();

    if (!r.ok) {
        return alert(d.error || "Scan failed.");
    }

    score.textContent = d.score;
    risk.textContent = d.risk + " RISK";

    summary.textContent =
        d.risk === "LOW"
            ? "No major signals detected."
            : "Review every finding before publication.";

    findings.innerHTML = d.findings.map(f => `
        <div class="finding">
            <b>${f.severity} · ${f.category}</b>

            <span class="muted">
                ${f.detail}
            </span>

            <div class="recommend">
                <b>Recommended action</b>
                ${f.recommendation}
            </div>
        </div>
    `).join("");

    // Keep the completed result visible for 10 seconds.
    setTimeout(() => {
        location.reload();
    }, 10000);
}


// ============================================================
// ALERT DETAILS
// ============================================================

function openAlert(button) {
    currentAlertId = button.dataset.id;

    const setText = (id, value, fallback = "Not recorded") => {
        const element = document.getElementById(id);

        if (element) {
            element.textContent =
                value !== undefined &&
                value !== null &&
                value !== ""
                    ? value
                    : fallback;
        }
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
        document.getElementById("alertScore");

    if (scoreElement) {
        scoreElement.textContent =
            button.dataset.score
                ? `${button.dataset.score}/100`
                : "Not recorded";
    }

    const closeButton =
        document.getElementById("alertCloseButton");

    if (closeButton) {
        closeButton.style.display =
            button.dataset.status === "Closed"
                ? "none"
                : "inline-block";
    }

    const caseButton =
        document.getElementById("alertCaseButton");

    if (caseButton) {
        if (button.dataset.status === "Open") {
            caseButton.style.display = "inline-block";
            caseButton.disabled = false;
            caseButton.textContent = "Create Case";
        } else {
            caseButton.style.display = "none";
        }
    }

    const modal =
        document.getElementById("alertModal");

    if (!modal) {
        alert("Alert window is missing from app.html.");
        return;
    }

    modal.style.display = "flex";
}


function closeAlertModal() {
    currentAlertId = null;

    const modal =
        document.getElementById("alertModal");

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

    await closeAlert(currentAlertId);
}


async function closeAlert(id) {
    const r = await fetch(
        "/api/alerts/" + id + "/close",
        {
            method: "POST",
            headers: {
                "X-CSRFToken": window.POSTGUARD_CSRF
            }
        }
    );

    if (!r.ok) {
        return alert("Could not close alert.");
    }

    location.reload();
}


// ============================================================
// CREATE CASE FROM ALERT
// ============================================================

async function createCaseFromAlert() {
    if (!currentAlertId) {
        return;
    }

    const button =
        document.getElementById("alertCaseButton");

    button.disabled = true;
    button.textContent = "Creating case...";

    const r = await fetch(
        "/api/alerts/" + currentAlertId + "/case",
        {
            method: "POST",
            headers: {
                "X-CSRFToken": window.POSTGUARD_CSRF
            }
        }
    );

    const d = await r.json();

    if (!r.ok) {
        button.disabled = false;
        button.textContent = "Create Case";

        return alert(
            d.error || "Could not create case."
        );
    }

    alert("Case created successfully.");

    location.reload();
}


// ============================================================
// CASES
// ============================================================

async function newCase() {
    const title = prompt("Case title");

    if (!title) {
        return;
    }

    await fetch("/api/cases", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": window.POSTGUARD_CSRF
        },
        body: JSON.stringify({
            title
        })
    });

    location.reload();
}


async function closeCase(id) {
    await fetch(
        "/api/cases/" + id + "/close",
        {
            method: "POST",
            headers: {
                "X-CSRFToken": window.POSTGUARD_CSRF
            }
        }
    );

    location.reload();
}


// ============================================================
// PRINCIPALS
// ============================================================

async function addPrincipal() {
    const name = prompt("Principal name");

    if (!name) {
        return;
    }

    const role =
        prompt("Role", "Executive") ||
        "Executive";

    await fetch("/api/principals", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": window.POSTGUARD_CSRF
        },
        body: JSON.stringify({
            name,
            role
        })
    });

    location.reload();
}


// ============================================================
// MONITORING SOURCES
// ============================================================

async function addSource() {
    const name = prompt("Source name");

    if (!name) {
        return;
    }

    const kind =
        prompt(
            "Source type",
            "Authorised social source"
        ) ||
        "Authorised source";

    await fetch("/api/sources", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": window.POSTGUARD_CSRF
        },
        body: JSON.stringify({
            name,
            kind
        })
    });

    location.reload();
}


// ============================================================
// AUDIT LOG
// ============================================================

async function loadAudit() {
    const r = await fetch("/api/audit");
    const d = await r.json();

    auditBox.textContent =
        d.map(x =>
            `${x.created_at} | ${x.email} | ${x.action} | ${x.detail}`
        ).join("\n") || "No events.";
}


// ============================================================
// KEYBOARD CONTROLS
// ============================================================

document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        closeAlertModal();
    }
});
