"use strict";

const telegram = window.Telegram?.WebApp;
const refreshButton = document.querySelector("#refresh");
const pageTitle = document.querySelector("#page-title");
const workspaceNav = document.querySelector("#workspace-nav");
const panelButtons = [...workspaceNav.querySelectorAll("[data-panel]")];
const formsView = document.querySelector("#forms-view");
const integrationsView = document.querySelector("#integrations-view");
const filters = document.querySelector("#filters");
const filterButtons = [...filters.querySelectorAll("[data-status]")];
const trashFilter = filters.querySelector('[data-status="deleted"]');
const counters = {
    total: document.querySelector("#count-all"),
    unviewed: document.querySelector("#count-new"),
    viewed: document.querySelector("#count-viewed"),
    deleted: document.querySelector("#count-deleted"),
};
const formList = document.querySelector("#forms");
const cardTemplate = document.querySelector("#form-card");
const listStatus = document.querySelector("#list-status");
const loadMore = document.querySelector("#load-more");

const dialog = document.querySelector("#details");
const detailTitle = document.querySelector("#detail-title");
const detailStatus = document.querySelector("#detail-status");
const detailContent = document.querySelector("#detail-content");
const detailName = document.querySelector("#detail-name");
const detailPhone = document.querySelector("#detail-phone");
const detailEmail = document.querySelector("#detail-email");
const detailDate = document.querySelector("#detail-date");
const detailMessage = document.querySelector("#detail-message");
const closeButton = document.querySelector("#close-details");
const retryDetails = document.querySelector("#retry-details");
const viewedButton = document.querySelector("#set-viewed");
const deleteButton = document.querySelector("#delete-form");
const restoreButton = document.querySelector("#restore-form");
const confirmation = document.querySelector("#confirm-delete");
const detailActions = document.querySelector("#detail-actions");
const cancelDelete = document.querySelector("#cancel-delete");
const acceptDelete = document.querySelector("#accept-delete");

let isAdmin = false;
let hasAccess = false;
let selectedPanel = new URLSearchParams(window.location.search).get("panel") === "integrations"
    ? "integrations" : "forms";
let selectedStatus = "all";
let nextCursor = null;
let openId = null;
let openForm = null;
let opener = null;
let accessRequest;
let listRequest;
let detailRequest;
let actionRequest;

class RequestError extends Error {
    constructor(status) {
        super(`HTTP ${status}`);
        this.status = status;
    }
}

async function api(path, signal, method = "GET", data) {
    const initData = telegram?.initData;
    if (!initData) throw new RequestError(401);

    const headers = { "X-Telegram-Init-Data": initData, Accept: "application/json" };
    if (data !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
        method,
        signal,
        headers,
        body: data === undefined ? undefined : JSON.stringify(data),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
    });
    if (!response.ok) throw new RequestError(response.status);

    return response.status === 204 ? null : response.json();
}

function showStatus(element, message = "", kind = "") {
    element.textContent = message;
    element.dataset.kind = kind;
}

const integrations = setupIntegrations({ api, showStatus, handleDenied });

function setDetailBusy(busy) {
    for (const button of [closeButton, viewedButton, deleteButton, restoreButton, cancelDelete, acceptDelete]) {
        button.disabled = busy;
    }
}

function closeDetails(restoreFocus = true) {
    detailRequest?.abort();
    detailRequest = null;
    openId = null;
    openForm = null;
    if (dialog.open) dialog.close();

    detailTitle.textContent = "Submission details";
    detailContent.hidden = true;
    retryDetails.hidden = true;
    confirmation.hidden = true;
    detailActions.hidden = false;
    setDetailBusy(false);
    showStatus(detailStatus);
    for (const field of [detailName, detailPhone, detailEmail, detailDate, detailMessage]) {
        field.replaceChildren();
    }

    if (restoreFocus && opener?.isConnected) opener.focus();
    opener = null;
}

function resetFormList() {
    listRequest?.abort();
    actionRequest?.abort();
    listRequest = null;
    actionRequest = null;
    closeDetails(false);

    nextCursor = null;
    filters.hidden = true;
    formList.replaceChildren();
    formList.removeAttribute("aria-busy");
    loadMore.hidden = true;
    loadMore.disabled = false;
    for (const counter of Object.values(counters)) counter.textContent = "0";
    showStatus(listStatus);
}

function clearPrivateData() {
    accessRequest?.abort();
    accessRequest = null;
    hasAccess = false;
    isAdmin = false;
    workspaceNav.hidden = true;
    formsView.hidden = true;
    integrationsView.hidden = true;
    trashFilter.hidden = true;
    refreshButton.disabled = false;
    resetFormList();
    integrations.reset();
}

function handleDenied(error) {
    if (error.status !== 401 && error.status !== 403) return false;

    const active = document.activeElement;
    const focusWasInPrivateView = dialog.open || [workspaceNav, formsView, integrationsView].some((node) => node.contains(active));
    clearPrivateData();
    if (focusWasInPrivateView) pageTitle.focus({ preventScroll: true });
    let message = "You don’t have access to submissions. Contact an administrator.";
    if (error.status === 401) {
        message = telegram?.initData
            ? "Your session has expired. Close the Mini App and reopen it from the bot menu."
            : "Open the Mini App from the bot menu in Telegram.";
    }
    showStatus(listStatus, message, "error");
    return true;
}

function showPanel(panel) {
    if (!hasAccess || (panel === "integrations" && !isAdmin)) return;
    selectedPanel = panel;
    for (const button of panelButtons) {
        button.setAttribute("aria-pressed", String(button.dataset.panel === panel));
    }

    const showIntegrations = panel === "integrations";
    formsView.hidden = showIntegrations;
    integrationsView.hidden = !showIntegrations;
    if (showIntegrations) {
        resetFormList();
        return integrations.refresh();
    }
    integrations.reset();
    filters.hidden = false;
    return loadPage();
}

function selectStatus(status) {
    selectedStatus = status;
    for (const button of filterButtons) {
        button.setAttribute("aria-pressed", String(button.dataset.status === status));
    }
}

async function refreshAccess() {
    const status = selectedStatus;
    const panel = selectedPanel;
    clearPrivateData();
    const request = new AbortController();
    accessRequest = request;
    refreshButton.disabled = true;
    showStatus(listStatus, "Checking access…");

    try {
        const profile = await api("/api/auth/me", request.signal);
        if (request.signal.aborted) return;

        hasAccess = true;
        isAdmin = profile.is_admin === true;
        workspaceNav.hidden = !isAdmin;
        trashFilter.hidden = !isAdmin;
        selectStatus(status === "deleted" && !isAdmin ? "all" : status);
        await showPanel(isAdmin ? panel : "forms");
    } catch (error) {
        if (!request.signal.aborted && !handleDenied(error)) {
            showStatus(listStatus, "Couldn’t check access. Select Refresh to try again.", "error");
        }
    } finally {
        if (accessRequest === request) {
            accessRequest = null;
            refreshButton.disabled = false;
        }
    }
}

function appendForm(form) {
    const card = cardTemplate.content.cloneNode(true);
    card.querySelector(".card-title").textContent = form.name || `Submission #${form.id}`;

    const badge = card.querySelector(".badge");
    badge.dataset.state = !form.deleted_at && !form.viewed ? "new" : "seen";
    badge.textContent = form.deleted_at ? "In trash" : form.viewed ? "Viewed" : "New";

    const timestamp = typeof form.timestamp === "string" ? form.timestamp.trim() : "";
    if (timestamp && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(timestamp)) {
        const date = card.querySelector("time");
        date.textContent = timestamp;
        date.dateTime = timestamp.replace(" ", "T");
    } else {
        card.querySelector(".card-date").textContent = timestamp || "No date provided";
    }

    const button = card.querySelector("[data-open]");
    button.setAttribute("aria-label", `Open submission #${form.id}`);
    button.addEventListener("click", () => openDetails(form.id, button));
    formList.append(card);
}

async function loadPage({ append = false, notice = "" } = {}) {
    if (!hasAccess || selectedPanel !== "forms" || (append && (listRequest || nextCursor === null))) return;

    listRequest?.abort();
    const request = new AbortController();
    listRequest = request;
    const query = new URLSearchParams({ status: selectedStatus });
    if (append) {
        query.set("before", String(nextCursor));
    } else {
        nextCursor = null;
        formList.replaceChildren();
        loadMore.hidden = true;
    }
    loadMore.disabled = true;
    formList.setAttribute("aria-busy", "true");
    showStatus(listStatus, notice || "Loading submissions…");

    try {
        const page = await api(`/api/forms?${query}`, request.signal);
        if (request.signal.aborted) return;

        for (const form of page.items) appendForm(form);
        for (const [key, counter] of Object.entries(counters)) {
            counter.textContent = String(page.counts[key] ?? 0);
        }
        nextCursor = page.next_cursor;
        loadMore.hidden = nextCursor === null;
        loadMore.disabled = false;
        if (notice) {
            showStatus(listStatus, notice);
        } else if (!formList.childElementCount) {
            showStatus(listStatus, "No submissions in this category yet.", "empty");
        } else {
            showStatus(listStatus);
        }
    } catch (error) {
        if (request.signal.aborted || handleDenied(error)) return;

        const failure = append
            ? "Couldn’t load more submissions. Try again."
            : "Couldn’t load submissions. Select Refresh to try again.";
        showStatus(listStatus, notice ? `${notice} ${failure}` : failure, "error");
        loadMore.disabled = false;
    } finally {
        if (listRequest === request) {
            listRequest = null;
            formList.removeAttribute("aria-busy");
        }
    }
}

function phoneLink(value) {
    if (!/^\+?[0-9 ().-]{7,32}$/.test(value)) return null;
    const normalized = value.replace(/[ ().-]/g, "");
    return /^\+?[0-9]{7,15}$/.test(normalized) ? `tel:${normalized}` : null;
}

function emailLink(value) {
    if (value.length > 254) return null;
    const match = /^([a-z0-9._%+\-]{1,64})@([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/i.exec(value);
    if (!match) return null;

    const [, local, domain] = match;
    if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
    if (domain.split(".").some((label) => label.length > 63 || label.startsWith("-") || label.endsWith("-"))) {
        return null;
    }
    return `mailto:${encodeURIComponent(local)}@${domain}`;
}

function renderContact(target, value, linkFor) {
    const field = target.parentElement;
    const text = typeof value === "string" ? value.trim() : "";
    field.hidden = !text;
    if (!text) return;

    const href = linkFor(text);
    if (!href) {
        target.textContent = text;
        return;
    }
    const link = document.createElement("a");
    link.href = href;
    link.textContent = text;
    target.replaceChildren(link);
}

function renderDetails(form) {
    openForm = form;
    const timestamp = typeof form.timestamp === "string" ? form.timestamp.trim() : "";
    detailName.textContent = form.name || "No name provided";
    detailDate.textContent = timestamp || "No date provided";
    detailMessage.textContent = form.message || "No message provided";
    renderContact(detailPhone, form.phone, phoneLink);
    renderContact(detailEmail, form.email, emailLink);

    const deleted = Boolean(form.deleted_at);
    viewedButton.hidden = deleted;
    viewedButton.textContent = form.viewed ? "Mark as new" : "Mark as viewed";
    deleteButton.hidden = deleted || !isAdmin;
    restoreButton.hidden = !deleted || !isAdmin;
    detailContent.hidden = false;
}

async function loadDetails() {
    const id = openId;
    detailRequest?.abort();
    const request = new AbortController();
    detailRequest = request;
    retryDetails.hidden = true;
    showStatus(detailStatus, "Loading submission…");

    try {
        const form = await api(`/api/forms/${id}`, request.signal);
        if (!request.signal.aborted) {
            renderDetails(form);
            showStatus(detailStatus);
        }
    } catch (error) {
        if (request.signal.aborted || handleDenied(error)) return;

        const missing = error.status === 404;
        showStatus(detailStatus, missing ? "This submission is no longer available." : "Couldn’t load the submission.", "error");
        retryDetails.hidden = missing;
    }
}

function openDetails(id, button) {
    if (!hasAccess || dialog.open || !Number.isSafeInteger(id) || id < 1) return;
    if (typeof dialog.showModal !== "function") {
        showStatus(listStatus, "Update Telegram or your browser to open this submission.", "error");
        return;
    }

    openId = id;
    opener = button;
    detailTitle.textContent = `Submission #${id}`;
    dialog.showModal();
    loadDetails();
}

async function changeForm(method, suffix, data, success) {
    if (!hasAccess || !openForm || actionRequest) return;

    const request = new AbortController();
    actionRequest = request;
    setDetailBusy(true);
    showStatus(detailStatus, "Saving changes…");

    try {
        await api(`/api/forms/${openId}${suffix}`, request.signal, method, data);
        if (request.signal.aborted) return;

        closeDetails(false);
        pageTitle.focus({ preventScroll: true });
        await loadPage({ notice: success });
    } catch (error) {
        if (request.signal.aborted || handleDenied(error)) return;

        const message = error.status === 404
            ? "This submission is no longer available. Close the details and refresh the list."
            : "Couldn’t save the change. Try again.";
        showStatus(detailStatus, message, "error");
    } finally {
        if (actionRequest === request) {
            actionRequest = null;
            setDetailBusy(false);
            if (dialog.open) {
                const firstAction = confirmation.hidden
                    ? [viewedButton, restoreButton].find((button) => !button.hidden)
                    : acceptDelete;
                firstAction?.focus();
            }
        }
    }
}

refreshButton.addEventListener("click", refreshAccess);
for (const button of panelButtons) {
    button.addEventListener("click", () => {
        if (selectedPanel !== button.dataset.panel) showPanel(button.dataset.panel);
    });
}
loadMore.addEventListener("click", () => loadPage({ append: true }));
for (const button of filterButtons) {
    button.addEventListener("click", () => {
        if (selectedStatus === button.dataset.status) return;
        selectStatus(button.dataset.status);
        loadPage();
    });
}

closeButton.addEventListener("click", () => closeDetails());
dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
    if (!actionRequest) closeDetails();
});
retryDetails.addEventListener("click", loadDetails);
viewedButton.addEventListener("click", () => {
    if (!openForm) return;
    const viewed = !openForm.viewed;
    changeForm("PATCH", "/viewed", { viewed }, viewed ? "Marked as viewed." : "Marked as new.");
});
deleteButton.addEventListener("click", () => {
    detailActions.hidden = true;
    confirmation.hidden = false;
    cancelDelete.focus();
});
cancelDelete.addEventListener("click", () => {
    confirmation.hidden = true;
    detailActions.hidden = false;
    deleteButton.focus();
});
acceptDelete.addEventListener("click", () => changeForm("DELETE", "", undefined, "Moved to trash."));
restoreButton.addEventListener("click", () => changeForm("POST", "/restore", undefined, "Submission restored."));

document.addEventListener("visibilitychange", () => {
    if (document.hidden) clearPrivateData();
    else refreshAccess();
});
window.addEventListener("pagehide", clearPrivateData);
window.addEventListener("pageshow", (event) => {
    if (event.persisted && !document.hidden) refreshAccess();
});

telegram?.ready?.();
telegram?.expand?.();
if (!document.hidden) refreshAccess();
