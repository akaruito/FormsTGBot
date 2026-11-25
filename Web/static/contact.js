"use strict";

const form = document.querySelector("#contact-form");
const phone = document.querySelector("#phone");
const email = document.querySelector("#email");
const submitButton = document.querySelector("#submit-button");
const submitStatus = document.querySelector("#submit-status");

function clearContactValidation() {
    phone.setCustomValidity("");
}

for (const field of [phone, email]) {
    field.addEventListener("input", clearContactValidation);
}

form.addEventListener("submit", (event) => {
    if (submitButton.disabled) {
        event.preventDefault();
        return;
    }
    if (!phone.value.trim() && !email.value.trim()) {
        event.preventDefault();
        phone.setCustomValidity("Enter a phone number or an email address.");
        phone.reportValidity();
        return;
    }
    submitButton.disabled = true;
    submitStatus.textContent = "Sending your message…";
});

window.addEventListener("pageshow", () => {
    clearContactValidation();
    submitButton.disabled = false;
    submitStatus.textContent = "";
});
