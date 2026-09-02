const names = {
    dashboard: "PostGuard Intelligence Centre",
    scanner: "AI Post Scanner",
    alerts: "Alert Queue",
    cases: "Case Management",
    people: "Principals",
    monitoring: "Authorised Monitoring",
    audit: "Audit Log"
};

function show(id, el) {
    document.querySelectorAll(".page").forEach(x => x.classList.remove("active"));
    document.getElementById(id).classList.add("active");

    document.querySelectorAll(".nav a").forEach(x => x.classList.remove("active"));

    if (el) {
        el.classList.add("active");
    }

    document.getElementById("crumb").textContent = names[id];

    if (id === "audit") {
        loadAudit();
    }
}

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
            <span class="muted">${f.detail}</span>
            <div class="recommend">
                <b>Recommended action</b>
                ${f.recommendation}
            </div>
        </div>
    `).join("");
}

async function closeAlert(id) {
    await fetch("/api/alerts/" + id + "/close", {
        method: "POST",
        headers: {
            "X-CSRFToken": window.POSTGUARD_CSRF
        }
    });

    location.reload();
}

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
        body: JSON.stringify({ title })
    });

    location.reload();
}

async function closeCase(id) {
    await fetch("/api/cases/" + id + "/close", {
        method: "POST",
        headers: {
            "X-CSRFToken": window.POSTGUARD_CSRF
        }
    });

    location.reload();
}

async function addPrincipal() {
    const name = prompt("Principal name");

    if (!name) {
        return;
    }

    const role = prompt("Role", "Executive") || "Executive";

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

async function addSource() {
    const name = prompt("Source name");

    if (!name) {
        return;
    }

    const kind =
        prompt("Source type", "Authorised social source") ||
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

async function loadAudit() {
    const r = await fetch("/api/audit");
    const d = await r.json();

    auditBox.textContent =
        d.map(x =>
            `${x.created_at} | ${x.email} | ${x.action} | ${x.detail}`
        ).join("\n") || "No events.";
}
