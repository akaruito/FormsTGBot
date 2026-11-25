"use strict";

function setupIntegrations({ api, showStatus, handleDenied }) {
    const panel = document.querySelector("#integrations-view");
    const form = panel.querySelector("#create-integration");
    const createButton = panel.querySelector("#create-integration-button");
    const originInput = panel.querySelector("#integration-origin");
    const list = panel.querySelector("#integration-list");
    const status = panel.querySelector("#integration-status");
    const cardTemplate = document.querySelector("#integration-card");
    const secretBox = panel.querySelector("#integration-secret");
    const secretValue = panel.querySelector("#integration-secret-value");
    const revokeDialog = panel.querySelector("#revoke-integration");
    const revokeStatus = panel.querySelector("#revoke-integration-status");
    const cancelRevoke = panel.querySelector("#cancel-revoke-integration");
    const confirmRevoke = panel.querySelector("#confirm-revoke-integration");
    const keyId = /^[A-Za-z0-9_-]{24}$/;
    const bearerKey = /^fsk_[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{43}$/;
    const dateFormat = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });
    let loading;
    let mutation;
    let keyToRevoke;

    function eraseSecret() {
        secretValue.value = "";
        secretBox.hidden = true;
    }

    function closeConfirmation() {
        keyToRevoke = null;
        if (revokeDialog.open) revokeDialog.close();
        showStatus(revokeStatus);
    }

    function setBusy(busy) {
        createButton.disabled = busy;
        cancelRevoke.disabled = busy;
        confirmRevoke.disabled = busy;
        for (const button of list.querySelectorAll("[data-revoke]")) button.disabled = busy;
    }

    function reset() {
        loading?.abort();
        mutation?.abort();
        loading = null;
        mutation = null;
        eraseSecret();
        closeConfirmation();
        form.reset();
        originInput.setCustomValidity("");
        list.replaceChildren();
        setBusy(false);
        showStatus(status);
    }

    function iframeCode(id) {
        const url = new URL(`/embed/${id}`, window.location.origin);
        if (url.protocol !== "https:") return null;

        const iframe = document.createElement("iframe");
        iframe.src = url.href;
        iframe.title = "Contact form";
        iframe.width = "100%";
        iframe.height = "720";
        iframe.loading = "lazy";
        iframe.sandbox.value = "allow-forms allow-scripts allow-same-origin";
        iframe.referrerPolicy = "no-referrer";
        return iframe.outerHTML;
    }

    async function copyValue(field, success) {
        if (panel.hidden || !field.value) return;
        try {
            await navigator.clipboard.writeText(field.value);
            if (!panel.hidden && field.isConnected && field.value) showStatus(status, success);
        } catch {
            if (panel.hidden || !field.isConnected || !field.value) return;
            field.focus();
            field.select();
            showStatus(status, "Copy the selected text.");
        }
    }

    function openConfirmation(id) {
        if (mutation || panel.hidden) return;
        if (typeof revokeDialog.showModal !== "function") {
            showStatus(status, "Update Telegram or your browser to revoke this key.", "error");
            return;
        }
        keyToRevoke = id;
        revokeDialog.showModal();
    }

    function makeCard(key) {
        const card = cardTemplate.content.cloneNode(true);
        card.querySelector(".card-title").textContent = key.label;
        card.querySelector(".integration-origin").textContent = key.origin;

        const revoked = Number.isFinite(key.revoked_at);
        const validExpiry = Number.isFinite(key.expires_at) && key.expires_at > 0 && key.expires_at < 9e12;
        const active = !revoked && validExpiry && key.expires_at > Date.now() / 1000;
        const badge = card.querySelector(".badge");
        badge.textContent = revoked ? "Revoked" : active ? "Active" : "Expired";
        if (active) badge.dataset.state = "new";

        if (validExpiry) {
            const expiry = dateFormat.format(new Date(key.expires_at * 1000));
            card.querySelector(".integration-date").textContent = `Expires ${expiry}`;
        }
        if (active) {
            const code = iframeCode(key.id);
            if (code) {
                const embed = card.querySelector(".integration-embed");
                const field = embed.querySelector("textarea");
                field.value = code;
                embed.hidden = false;
                embed.querySelector("[data-copy-embed]").addEventListener(
                    "click", () => copyValue(field, "Embed code copied."),
                );
            }
            card.querySelector("[data-integration-actions]").hidden = false;
            card.querySelector("[data-revoke]").addEventListener("click", () => openConfirmation(key.id));
        }
        return card;
    }

    async function refresh(notice = "") {
        if (panel.hidden) return;
        loading?.abort();
        const request = new AbortController();
        loading = request;
        showStatus(status, notice || "Loading API keys…");

        try {
            const page = await api("/api/admin/api-keys", request.signal);
            if (request.signal.aborted) return;
            const cards = page.items.filter((key) => typeof key.id === "string" && keyId.test(key.id)).map(makeCard);
            list.replaceChildren(...cards);
            setBusy(Boolean(mutation));
            showStatus(status, notice || (cards.length ? "" : "No API keys yet."));
        } catch (error) {
            if (request.signal.aborted || handleDenied(error)) return;
            const errorMessage = "Couldn’t load API keys. Select Refresh to try again.";
            showStatus(status, notice ? `${notice} ${errorMessage}` : errorMessage, "error");
        } finally {
            if (loading === request) loading = null;
        }
    }

    async function create(event) {
        event.preventDefault();
        if (mutation || panel.hidden) return;

        let site;
        try {
            site = new URL(originInput.value.trim());
            if (site.protocol !== "https:" || site.username || site.password || site.pathname !== "/" || site.search || site.hash) {
                throw new Error("invalid origin");
            }
        } catch {
            originInput.setCustomValidity("Enter the website’s HTTPS address without a path, query, or credentials.");
            originInput.reportValidity();
            return;
        }

        const values = new FormData(form);
        const request = new AbortController();
        mutation = request;
        setBusy(true);
        eraseSecret();
        showStatus(status, "Creating key…");

        try {
            const response = await api("/api/admin/api-keys", request.signal, "POST", {
                label: values.get("label").trim(),
                origin: site.origin,
                expires_days: Number(values.get("expires_days")),
            });
            if (request.signal.aborted) return;
            if (typeof response.secret !== "string" || !bearerKey.test(response.secret)) {
                showStatus(status, "Couldn’t display the secret key. Refresh the list, revoke the key, and create a new one.", "error");
                return;
            }

            form.reset();
            secretValue.value = response.secret;
            secretBox.hidden = false;
            secretValue.focus({ preventScroll: true });
            await refresh("Key created.");
        } catch (error) {
            if (request.signal.aborted || handleDenied(error)) return;
            let message = "Couldn’t create the key. Refresh the list before trying again.";
            if (error.status === 400) message = "Check the name, HTTPS address, and expiration.";
            if (error.status === 409 || error.status === 429) message = "You’ve reached the key creation limit. Check your active keys.";
            showStatus(status, message, "error");
        } finally {
            if (mutation === request) {
                mutation = null;
                setBusy(false);
            }
        }
    }

    async function revoke() {
        if (mutation || panel.hidden || !keyToRevoke) return;
        const request = new AbortController();
        mutation = request;
        setBusy(true);
        showStatus(revokeStatus, "Revoking key…");
        try {
            await api(`/api/admin/api-keys/${keyToRevoke}`, request.signal, "DELETE");
            if (request.signal.aborted) return;
            eraseSecret();
            closeConfirmation();
            createButton.focus({ preventScroll: true });
            await refresh("Key revoked.");
        } catch (error) {
            if (request.signal.aborted || handleDenied(error)) return;
            showStatus(revokeStatus, "Couldn’t revoke the key. Try again.", "error");
        } finally {
            if (mutation === request) {
                mutation = null;
                setBusy(false);
            }
        }
    }

    form.addEventListener("submit", create);
    originInput.addEventListener("input", () => originInput.setCustomValidity(""));
    panel.querySelector("#copy-secret").addEventListener("click", () => copyValue(secretValue, "Key copied."));
    panel.querySelector("#hide-secret").addEventListener("click", () => {
        eraseSecret();
        createButton.focus();
    });
    cancelRevoke.addEventListener("click", closeConfirmation);
    confirmRevoke.addEventListener("click", revoke);
    revokeDialog.addEventListener("cancel", (event) => {
        event.preventDefault();
        if (!mutation) closeConfirmation();
    });

    return { refresh, reset };
}
