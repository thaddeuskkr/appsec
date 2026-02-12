(() => {
    function findPasswordField(button) {
        const targetId = button.getAttribute("data-target");
        if (targetId) {
            return document.getElementById(targetId);
        }

        return button.closest(".input-group")?.querySelector("input[type='password'], input[type='text']") ?? null;
    }

    function updateToggleVisual(button, isVisible) {
        const icon = button.querySelector("i");
        if (icon) {
            icon.classList.toggle("bi-eye", !isVisible);
            icon.classList.toggle("bi-eye-slash", isVisible);
        }

        button.setAttribute("aria-label", isVisible ? "Hide password" : "Show password");
        button.setAttribute("aria-pressed", String(isVisible));
    }

    function attachPasswordToggles() {
        document.querySelectorAll("[data-password-toggle]").forEach((button) => {
            if (button.dataset.bound === "1") {
                return;
            }

            button.dataset.bound = "1";
            updateToggleVisual(button, false);

            button.addEventListener("click", () => {
                const field = findPasswordField(button);
                if (!field) {
                    return;
                }

                const show = field.type === "password";
                field.type = show ? "text" : "password";
                updateToggleVisual(button, show);
            });
        });
    }

    function setLoadingState(form) {
        const submitters = form.querySelectorAll("button[type='submit'], input[type='submit']");
        submitters.forEach((submitter) => {
            submitter.setAttribute("disabled", "disabled");

            const loadingText = submitter.getAttribute("data-loading-text");
            if (!loadingText) {
                return;
            }

            if (submitter.tagName === "BUTTON") {
                submitter.dataset.originalText = submitter.textContent ?? "";
                submitter.textContent = loadingText;
            } else {
                submitter.dataset.originalText = submitter.getAttribute("value") ?? "";
                submitter.setAttribute("value", loadingText);
            }
        });
    }

    function showClientError(form, message) {
        let errorBox = form.querySelector("[data-client-error='true']");
        if (!errorBox) {
            errorBox = document.createElement("div");
            errorBox.className = "alert alert-danger mt-2";
            errorBox.setAttribute("data-client-error", "true");
            form.prepend(errorBox);
        }

        errorBox.textContent = message;
    }

    async function executeRecaptcha(siteKey, action) {
        if (typeof grecaptcha === "undefined") {
            throw new Error("reCAPTCHA script is unavailable.");
        }

        return new Promise((resolve, reject) => {
            grecaptcha.ready(() => {
                grecaptcha.execute(siteKey, { action })
                    .then(resolve)
                    .catch(reject);
            });
        });
    }

    async function primeRecaptcha(form) {
        const recaptchaAction = form.getAttribute("data-recaptcha-action");
        const recaptchaSiteKey = form.getAttribute("data-recaptcha-site-key");
        const tokenInput = form.querySelector("[data-recaptcha-token='true']");
        const needsRecaptcha = !!(recaptchaAction && recaptchaSiteKey && tokenInput);

        if (!needsRecaptcha || form.dataset.recaptchaPrimed === "1") {
            return;
        }

        try {
            const token = await executeRecaptcha(recaptchaSiteKey, recaptchaAction);
            tokenInput.value = token;
            form.dataset.recaptchaPrimed = "1";
        } catch {
            tokenInput.value = "";
        }
    }

    function attachEnhancedFormHandlers() {
        document.querySelectorAll("form[data-enhanced-form], form[data-recaptcha-action]").forEach((form) => {
            if (form.dataset.bound === "1") {
                return;
            }

            form.dataset.bound = "1";
            primeRecaptcha(form);

            form.addEventListener("submit", async (event) => {
                if (form.dataset.submitting === "1") {
                    event.preventDefault();
                    return;
                }

                const recaptchaAction = form.getAttribute("data-recaptcha-action");
                const recaptchaSiteKey = form.getAttribute("data-recaptcha-site-key");
                const tokenInput = form.querySelector("[data-recaptcha-token='true']");
                const needsRecaptcha = !!(recaptchaAction && recaptchaSiteKey && tokenInput);

                if (needsRecaptcha && form.dataset.recaptchaBypass !== "1") {
                    event.preventDefault();

                    try {
                        const token = await executeRecaptcha(recaptchaSiteKey, recaptchaAction);
                        tokenInput.value = token;
                        form.dataset.recaptchaBypass = "1";
                    } catch {
                        tokenInput.value = "";
                        form.dataset.recaptchaBypass = "0";
                        showClientError(form, "Could not validate reCAPTCHA right now. Please refresh and try again.");
                        return;
                    }

                    if (typeof form.requestSubmit === "function") {
                        form.requestSubmit(event.submitter ?? undefined);
                    } else {
                        form.submit();
                    }

                    return;
                }

                if (form.dataset.recaptchaBypass === "1") {
                    form.dataset.recaptchaBypass = "0";
                }

                form.dataset.submitting = "1";
                setLoadingState(form);
            });
        });
    }

    document.addEventListener("DOMContentLoaded", () => {
        attachPasswordToggles();
        attachEnhancedFormHandlers();
    });
})();
