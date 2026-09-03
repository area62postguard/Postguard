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
    const id = button.dataset.id;
    const severity = button.dataset.severity;
    const category = button.dataset.category;
    const principal = button.dataset.principal;
    const detail = button.dataset.detail;
    const recommendation = button.dataset.recommendation;
    const score = button.dataset.score;
    const caption = button.dataset.caption;
    const checkId = button.dataset.checkId;
    const status = button.dataset.status;
    const createdAt = button.dataset.created;

    currentAlertId = id;

    document.getElementById("alertTitle").textContent =
        category || "Alert details";

    document.getElementById("alertSeverity").textContent =
        severity || "Unknown";

    document.getElementById("alertScore").textContent =
        score ? `${score}/100` : "Not recorded";

    document.getElementById("alertPrincipal").textContent =
        principal || "Unassigned";

    document.getElementById("alertCheckId").textContent =
        checkId || "Not recorded";

    document.getElementById("alertCaption").textContent =
        caption || "Not recorded.";

    document.getElementById("alertStatus").textContent =
        status || "Unknown";

    document.getElementById("alertCreated").textContent =
        createdAt || "Unknown";

    document.getElementById("alertDetail").textContent =
        detail || "No detail recorded.";

    document.getElementById("alertRecommendation").textContent =
        recommendation || "No recommendation recorded.";

    const closeButton =
        document.getElementById("alertCloseButton");

    if (status === "Open" || status === "In Case") {
        closeButton.style.display = "inline-block";
    } else {
        closeButton.style.display = "none";
    }

    const caseButton =
        document.getElementById("alertCaseButton");

    if (status === "Open") {
        caseButton.style.display = "inline-block";
        caseButton.disabled = false;
        caseButton.textContent = "Create Case";
    } else {
        caseButton.style.display = "none";
    }

    const modal =
        document.getElementById("alertModal");

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
