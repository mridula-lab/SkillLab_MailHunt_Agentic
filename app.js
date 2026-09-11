/* =========================================================
   MAIL HUNT - AI Email Threat Detection
   Modular Front-end Prototype Engine & Application Logic
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {
    "use strict";

    /* =====================================================
       1. PERSISTENCE & GLOBAL STATE
       ===================================================== */

    const STORAGE = {
        user: "mailHuntUser",
        history: "mailHuntHistory",
        stats: "mailHuntStats",
        settings: "mailHuntSettings"
    };

    function safeJSONParse(key, fallback) {
        try {
            const raw = localStorage.getItem(key);
            if (!raw) return fallback;
            return JSON.parse(raw);
        } catch (e) {
            console.warn(`[MailHunt] Failed to parse localStorage key "${key}":`, e);
            return fallback;
        }
    }

    const state = {
        user: safeJSONParse(STORAGE.user, null),
        selectedFile: null,
        selectedFileName: "",
        selectedFileContent: "",
        currentResult: null,
        history: safeJSONParse(STORAGE.history, []),
        stats: safeJSONParse(STORAGE.stats, {
            scanned: 24,
            threats: 7,
            high: 3,
            suspicious: 2,
            safe: 2
        }),
        settings: safeJSONParse(STORAGE.settings, {
            alerts: true,
            autoScan: true,
            linkWarnings: true,
            language: "English",
            theme: "light"
        })
    };


    /* =====================================================
       2. DOM ELEMENTS
       ===================================================== */

    // Navigation & Layout
    const sidebar = document.getElementById("sidebar");
    const menuButton = document.getElementById("menuButton");
    const toast = document.getElementById("toast");

    // Login Form
    const loginForm = document.getElementById("loginForm");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const showPasswordButton = document.getElementById("showPassword");
    const forgotPasswordTrigger = document.querySelector(".forgot-button");
    const signUpTrigger = document.querySelector(".signup .link-button");

    // Upload Screen
    const fileInput = document.getElementById("emailFile");
    const browseButton = document.getElementById("browseButton");
    const uploadBox = document.querySelector(".upload-box");
    const selectedFileElement = document.getElementById("selectedFile");
    const scanButton = document.getElementById("scanButton");

    // Scanning Screen
    const scanningFile = document.getElementById("scanningFile");
    const scanMessage = document.getElementById("scanMessage");
    const progressBar = document.querySelector(".progress");
    const check1 = document.getElementById("check1");
    const check2 = document.getElementById("check2");
    const check3 = document.getElementById("check3");
    const check4 = document.getElementById("check4");

    // Result Screen
    const resultCard = document.getElementById("resultCard") || document.querySelector(".result-card");
    const resultIcon = document.getElementById("resultIcon") || document.querySelector(".danger-icon");
    const resultLabel = document.getElementById("resultLabel") || document.querySelector(".result-label");
    const resultHeading = document.getElementById("resultHeading") || document.querySelector(".result-card h2");
    const resultFile = document.getElementById("resultFile");
    const riskScoreLabel = document.getElementById("riskScoreLabel");
    const riskScoreFill = document.getElementById("riskScoreFill");
    const explanationList = document.getElementById("explanationList") || document.querySelector(".explanation-card ul");
    const indicatorsList = document.getElementById("indicatorsList");
    const technicalResultInfo = document.getElementById("technicalResultInfo");
    const downloadReportButton = document.getElementById("downloadReportButton");
    const scanAnotherButton = document.getElementById("scanAnotherButton");

    // History Screen
    const historyList = document.getElementById("historyList");
    const clearHistoryButton = document.getElementById("clearHistoryButton");

    // Reports Screen
    const emailsScanned = document.getElementById("emailsScanned");
    const threatsDetected = document.getElementById("threatsDetected");
    const statHigh = document.getElementById("statHigh");
    const statSuspicious = document.getElementById("statSuspicious");
    const statSafe = document.getElementById("statSafe");
    const riskChart = document.getElementById("riskChart");
    const recentThreatsList = document.getElementById("recentThreatsList");

    // Settings Screen
    const accountEmail = document.getElementById("accountEmail");
    const settingAlerts = document.getElementById("settingAlerts");
    const settingAutoScan = document.getElementById("settingAutoScan");
    const settingLinkWarnings = document.getElementById("settingLinkWarnings");
    const settingLanguage = document.getElementById("settingLanguage");
    const themeSelect = document.getElementById("themeSelect");

    // Modals
    const signupModal = document.getElementById("signupModal");
    const signupForm = document.getElementById("signupForm");
    const signupEmail = document.getElementById("signupEmail");
    const signupPassword = document.getElementById("signupPassword");
    const closeSignupModal = document.getElementById("closeSignupModal");
    const cancelSignupBtn = document.getElementById("cancelSignupBtn");

    const forgotModal = document.getElementById("forgotModal");
    const forgotForm = document.getElementById("forgotForm");
    const forgotEmail = document.getElementById("forgotEmail");
    const closeForgotModal = document.getElementById("closeForgotModal");
    const cancelForgotBtn = document.getElementById("cancelForgotBtn");


    /* =====================================================
       3. SCREEN NAVIGATION
       ===================================================== */

    const validScreens = [
        "login",
        "upload",
        "scanning",
        "menu",
        "result",
        "history",
        "reports",
        "settings"
    ];

    function showScreen(screenName) {
        if (!validScreens.includes(screenName)) return;

        // Hide all screens
        document.querySelectorAll(".screen").forEach(screen => {
            screen.classList.remove("active");
        });

        // Show target screen
        const targetScreen = document.getElementById(screenName);
        if (targetScreen) {
            targetScreen.classList.add("active");
        }

        // Update active nav button
        document.querySelectorAll(".nav-item").forEach(button => {
            button.classList.remove("active");
            if (button.dataset.screen === screenName) {
                button.classList.add("active");
            }
        });

        // Trigger screen-specific rendering
        if (screenName === "settings") {
            renderSettings();
        } else if (screenName === "history") {
            renderHistory();
        } else if (screenName === "reports") {
            updateReports();
        }

        // Close sidebar on mobile
        if (sidebar) {
            sidebar.classList.remove("open");
        }

        window.scrollTo({ top: 0, behavior: "smooth" });
    }

    // Global navigation delegate
    document.addEventListener("click", event => {
        const button = event.target.closest("[data-screen]");
        if (!button) return;

        const screenName = button.dataset.screen;

        // Logout action
        if (button.classList.contains("logout")) {
            logout();
            return;
        }

        // View historical scan result
        if (button.dataset.historyId) {
            const record = state.history.find(item => item.id === button.dataset.historyId);
            if (record && record.result) {
                state.currentResult = record.result;
                renderResult(record.result);
                showScreen("result");
            }
            return;
        }

        // Scan Another action
        if (button === scanAnotherButton || screenName === "upload") {
            resetUploadState();
        }

        showScreen(screenName);
    });

    // Mobile Sidebar toggle
    if (menuButton) {
        menuButton.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });
    }

    // Close sidebar on outside click (mobile)
    document.addEventListener("click", event => {
        if (sidebar && sidebar.classList.contains("open")) {
            const isClickInsideSidebar = sidebar.contains(event.target);
            const isClickOnMenuButton = menuButton && menuButton.contains(event.target);
            if (!isClickInsideSidebar && !isClickOnMenuButton) {
                sidebar.classList.remove("open");
            }
        }
    });

    // Close sidebar on Escape key
    document.addEventListener("keydown", event => {
        if (event.key === "Escape") {
            if (sidebar) sidebar.classList.remove("open");
            closeAllModals();
        }
    });


    /* =====================================================
       4. AUTHENTICATION & LOGIN (PROTOTYPE DEMO)
       ===================================================== */

    if (loginForm) {
        loginForm.addEventListener("submit", event => {
            event.preventDefault();

            const email = emailInput.value.trim();
            const password = passwordInput.value.trim();

            if (!email) {
                showToast("Please enter your email");
                emailInput.focus();
                return;
            }

            if (!isValidEmail(email)) {
                showToast("Please enter a valid email address");
                emailInput.focus();
                return;
            }

            if (!password) {
                showToast("Please enter your password");
                passwordInput.focus();
                return;
            }

            // Save login session locally
            state.user = {
                email: email,
                loginTime: new Date().toISOString()
            };
            localStorage.setItem(STORAGE.user, JSON.stringify(state.user));

            updateAccountEmail();
            showToast("Signed in successfully");

            setTimeout(() => {
                showScreen("upload");
            }, 450);
        });
    }

    // Password Show / Hide toggle
    if (showPasswordButton && passwordInput) {
        showPasswordButton.addEventListener("click", () => {
            const isPassword = passwordInput.type === "password";
            passwordInput.type = isPassword ? "text" : "password";
            showPasswordButton.textContent = isPassword ? "◉" : "◌";
            showPasswordButton.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
        });
    }

    // Sign Up Modal Handlers
    if (signUpTrigger) {
        signUpTrigger.addEventListener("click", () => {
            openModal(signupModal);
            if (signupEmail) signupEmail.focus();
        });
    }

    if (signupForm) {
        signupForm.addEventListener("submit", event => {
            event.preventDefault();
            const email = signupEmail.value.trim();
            const password = signupPassword.value.trim();

            if (!email || !isValidEmail(email)) {
                showToast("Please enter a valid email address");
                return;
            }
            if (!password) {
                showToast("Please choose a password");
                return;
            }

            state.user = {
                email: email,
                loginTime: new Date().toISOString()
            };
            localStorage.setItem(STORAGE.user, JSON.stringify(state.user));

            if (emailInput) emailInput.value = email;
            if (passwordInput) passwordInput.value = password;

            updateAccountEmail();
            closeAllModals();
            showToast("Account registered! Welcome to Mail Hunt");

            setTimeout(() => {
                showScreen("upload");
            }, 500);
        });
    }

    if (closeSignupModal) closeSignupModal.addEventListener("click", () => closeModal(signupModal));
    if (cancelSignupBtn) cancelSignupBtn.addEventListener("click", () => closeModal(signupModal));

    // Forgot Password Modal Handlers
    if (forgotPasswordTrigger) {
        forgotPasswordTrigger.addEventListener("click", () => {
            openModal(forgotModal);
            if (forgotEmail) forgotEmail.focus();
        });
    }

    if (forgotForm) {
        forgotForm.addEventListener("submit", event => {
            event.preventDefault();
            const email = forgotEmail.value.trim();
            if (!email || !isValidEmail(email)) {
                showToast("Please enter a valid email address");
                return;
            }
            closeAllModals();
            showToast(`Password reset instructions sent to ${email}`);
        });
    }

    if (closeForgotModal) closeForgotModal.addEventListener("click", () => closeModal(forgotModal));
    if (cancelForgotBtn) cancelForgotBtn.addEventListener("click", () => closeModal(forgotModal));

    function openModal(modal) {
        if (!modal) return;
        modal.removeAttribute("hidden");
    }

    function closeModal(modal) {
        if (!modal) return;
        modal.setAttribute("hidden", "");
    }

    function closeAllModals() {
        closeModal(signupModal);
        closeModal(forgotModal);
    }

    // Backdrop click dismiss
    [signupModal, forgotModal].forEach(modal => {
        if (modal) {
            modal.addEventListener("click", event => {
                if (event.target === modal) {
                    closeModal(modal);
                }
            });
        }
    });

    function logout() {
        state.user = null;
        localStorage.removeItem(STORAGE.user);

        if (emailInput) emailInput.value = "";
        if (passwordInput) passwordInput.value = "";

        updateAccountEmail();
        showToast("You have been logged out");

        setTimeout(() => {
            showScreen("login");
        }, 350);
    }


    /* =====================================================
       5. EMAIL FILE UPLOAD & DRAG/DROP
       ===================================================== */

    if (browseButton && fileInput) {
        browseButton.addEventListener("click", () => {
            fileInput.click();
        });
    }

    if (fileInput) {
        fileInput.addEventListener("change", () => {
            if (!fileInput.files.length) return;
            handleSelectedFile(fileInput.files[0]);
        });
    }

    // Drag & Drop handlers
    if (uploadBox) {
        ["dragenter", "dragover"].forEach(eventName => {
            uploadBox.addEventListener(eventName, event => {
                event.preventDefault();
                uploadBox.style.borderColor = "var(--teal)";
                uploadBox.style.background = "#f2fbfc";
            });
        });

        ["dragleave", "drop"].forEach(eventName => {
            uploadBox.addEventListener(eventName, event => {
                event.preventDefault();
                uploadBox.style.borderColor = "";
                uploadBox.style.background = "";
            });
        });

        uploadBox.addEventListener("drop", event => {
            const files = event.dataTransfer ? event.dataTransfer.files : [];
            if (!files || !files.length) return;
            handleSelectedFile(files[0]);
        });
    }

    function handleSelectedFile(file) {
        const allowedExtensions = [".eml", ".msg", ".txt", ".html", ".htm"];
        const extension = "." + file.name.split(".").pop().toLowerCase();

        if (!allowedExtensions.includes(extension)) {
            showToast("Unsupported format. Use .EML, .MSG, .TXT, or .HTML");
            return;
        }

        // 10 MB maximum file size limit
        if (file.size > 10 * 1024 * 1024) {
            showToast("File is too large. Maximum allowed size is 10 MB");
            return;
        }

        state.selectedFile = file;
        state.selectedFileName = file.name;
        state.selectedFileContent = "";

        if (selectedFileElement) {
            selectedFileElement.textContent = `✓ ${file.name} ready for inspection`;
        }

        if (scanButton) {
            scanButton.disabled = false;
        }

        showToast("Email file attached successfully");
    }

    function resetUploadState() {
        state.selectedFile = null;
        state.selectedFileName = "";
        state.selectedFileContent = "";
        if (fileInput) fileInput.value = "";
        if (selectedFileElement) selectedFileElement.textContent = "";
        if (scanButton) scanButton.disabled = true;
    }


    /* =====================================================
       6. SCANNING SEQUENCE & EXECUTION
       ===================================================== */

    if (scanButton) {
        scanButton.addEventListener("click", startScan);
    }

    async function startScan() {
        if (!state.selectedFile) {
            showToast("Please select an email file first");
            return;
        }

        showScreen("scanning");

        if (scanningFile) {
            scanningFile.textContent = state.selectedFileName;
        }

        resetScanningUI();

        // Read file contents
        const content = await readEmailFile(state.selectedFile);
        state.selectedFileContent = content;

        // Realistic multi-stage scanning pipeline
        const steps = [
            {
                percent: 25,
                element: check1,
                text: "✓ Sender reputation checked",
                message: "Checking suspicious links..."
            },
            {
                percent: 50,
                element: check2,
                text: "✓ Suspicious links checked",
                message: "Analyzing message language..."
            },
            {
                percent: 75,
                element: check3,
                text: "✓ Urgent language analyzed",
                message: "Inspecting attachments..."
            },
            {
                percent: 90,
                element: check4,
                text: "✓ Attachments inspected",
                message: "Generating AI threat assessment..."
            }
        ];

        for (const step of steps) {
            await wait(600);
            if (progressBar) progressBar.style.width = step.percent + "%";
            if (step.element) step.element.textContent = step.text;
            if (scanMessage) scanMessage.textContent = step.message;
        }

        await wait(600);

        if (progressBar) progressBar.style.width = "100%";
        if (scanMessage) scanMessage.textContent = "Threat assessment completed";

        // Execute heuristic threat detection
        const result = analyzeEmail(state.selectedFileName, state.selectedFileContent);
        state.currentResult = result;

        // Save scan to history & stats
        saveScan(result);

        await wait(450);

        renderResult(result);
        showScreen("result");
    }

    function resetScanningUI() {
        if (progressBar) progressBar.style.width = "0%";
        if (scanMessage) scanMessage.textContent = "Checking sender reputation...";
        if (check1) check1.textContent = "◌ Sender reputation";
        if (check2) check2.textContent = "◌ Suspicious links";
        if (check3) check3.textContent = "◌ Urgent language";
        if (check4) check4.textContent = "◌ Attachments";
    }

    function readEmailFile(file) {
        return new Promise(resolve => {
            const extension = "." + file.name.split(".").pop().toLowerCase();

            // .msg is a binary OLE compound file format
            if (extension === ".msg") {
                const reader = new FileReader();
                reader.onload = event => {
                    const buffer = event.target.result;
                    let textExtract = "";
                    if (buffer) {
                        // Safely extract printable ASCII/UTF-8 strings from binary stream
                        const bytes = new Uint8Array(buffer);
                        let currentStr = "";
                        for (let i = 0; i < Math.min(bytes.length, 250000); i++) {
                            const b = bytes[i];
                            if ((b >= 32 && b <= 126) || b === 10 || b === 13) {
                                currentStr += String.fromCharCode(b);
                            } else {
                                if (currentStr.length >= 4) {
                                    textExtract += currentStr + " ";
                                }
                                currentStr = "";
                            }
                        }
                    }
                    resolve(textExtract);
                };
                reader.onerror = () => resolve("");
                reader.readAsArrayBuffer(file);
                return;
            }

            // Text / EML / HTML formats
            const reader = new FileReader();
            reader.onload = event => resolve(event.target.result || "");
            reader.onerror = () => resolve("");
            reader.readAsText(file);
        });
    }


    /* =====================================================
       7. MODULAR EMAIL ANALYSIS ENGINE
       (Designed to be cleanly replaced by Flask backend API)
       ===================================================== */

    /**
     * analyzeEmail - Heuristic & Rule-Based Threat Analysis
     * @param {string} fileName - Uploaded file name
     * @param {string} rawContent - Raw text or extracted email content
     * @returns {Object} Structured threat analysis payload
     */
    function analyzeEmail(fileName, rawContent) {
        const content = String(rawContent || "");
        const lower = content.toLowerCase();
        const lowerFileName = fileName.toLowerCase();

        let score = 0;
        const reasons = [];
        const indicators = [];

        /* -------------------------------------------------
           A. SENDER REPUTATION & HEADER ANALYSIS
           ------------------------------------------------- */
        const fromHeader = getHeader(content, "From");
        const replyToHeader = getHeader(content, "Reply-To");
        const sender = extractEmailAddress(fromHeader);
        const replyTo = extractEmailAddress(replyToHeader);

        let senderDomain = "";
        if (sender && sender.includes("@")) {
            senderDomain = sender.split("@")[1].toLowerCase();
        }

        let replyDomain = "";
        if (replyTo && replyTo.includes("@")) {
            replyDomain = replyTo.split("@")[1].toLowerCase();
        }

        // Check Punycode / IDN homograph attacks
        if (senderDomain && senderDomain.includes("xn--")) {
            score += 25;
            reasons.push(`Suspicious Punycode (IDN homograph) sender domain detected: "${senderDomain}"`);
            indicators.push("Punycode domain (xn--)");
        }

        // Check IP address based sender domain
        if (senderDomain && looksLikeIPAddress(senderDomain)) {
            score += 30;
            reasons.push(`Sender domain uses a raw IP address: "${senderDomain}"`);
            indicators.push("IP-based sender domain");
        }

        // Suspicious / high-abuse top-level domains & lookalike keywords
        const suspiciousTLDs = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click", ".work", ".rest", ".space"];
        if (senderDomain && suspiciousTLDs.some(tld => senderDomain.endsWith(tld))) {
            score += 15;
            reasons.push(`Sender uses a domain extension frequently abused in phishing: "${senderDomain}"`);
            indicators.push("Suspicious domain TLD");
        }

        const spoofedBrandPatterns = ["paypal-", "support-apple", "netflix-billing", "chase-verify", "microsoft-security", "google-account-verify"];
        if (senderDomain && spoofedBrandPatterns.some(pat => senderDomain.includes(pat))) {
            score += 30;
            reasons.push(`Sender domain mimics a known security/billing brand: "${senderDomain}"`);
            indicators.push("Brand spoofing domain");
        }

        // Domain mismatch between From and Reply-To
        if (senderDomain && replyDomain && senderDomain !== replyDomain) {
            score += 25;
            reasons.push(`Sender domain (${senderDomain}) does not match Reply-To domain (${replyDomain})`);
            indicators.push("Sender & Reply-To domain mismatch");
        }


        /* -------------------------------------------------
           B. URL DETECTION & REPUTATION
           ------------------------------------------------- */
        const urls = extractURLs(content);
        const suspiciousUrls = urls.filter(isSuspiciousURL);

        if (urls.length > 0) {
            indicators.push(`${urls.length} link(s) detected`);
        }

        if (suspiciousUrls.length > 0) {
            score += Math.min(35, suspiciousUrls.length * 15);
            reasons.push(`${suspiciousUrls.length} suspicious link(s) detected (e.g. shorteners, IP hosts, or credential patterns)`);
            indicators.push("Suspicious link(s)");
        }


        /* -------------------------------------------------
           C. URGENCY / SOCIAL ENGINEERING
           ------------------------------------------------- */
        const urgencyPatterns = [
            "urgent",
            "immediately",
            "act now",
            "verify now",
            "final warning",
            "account suspended",
            "account will be closed",
            "immediate action",
            "within 24 hours",
            "last warning",
            "respond immediately",
            "action required"
        ];
        const urgencyMatches = findMatches(lower, urgencyPatterns);

        if (urgencyMatches.length > 0) {
            score += Math.min(20, urgencyMatches.length * 7);
            reasons.push(`High-pressure/urgent phrasing detected: "${urgencyMatches.slice(0, 3).join('", "')}"`);
            indicators.push("Urgent / pressure language");
        }


        /* -------------------------------------------------
           D. FINANCIAL THREATS & PAYMENT REQUESTS
           ------------------------------------------------- */
        const financialPatterns = [
            "payment",
            "pay immediately",
            "transfer money",
            "bank transfer",
            "wire transfer",
            "upi",
            "invoice",
            "refund",
            "gift card",
            "cryptocurrency",
            "crypto",
            "bitcoin",
            "credit card",
            "debit card",
            "overdue payment"
        ];
        const financialMatches = findMatches(lower, financialPatterns);

        if (financialMatches.length > 0) {
            score += Math.min(25, financialMatches.length * 8);
            reasons.push(`Financial transaction/payment demand detected: "${financialMatches.slice(0, 3).join('", "')}"`);
            indicators.push("Financial request");
        }


        /* -------------------------------------------------
           E. CREDENTIAL PHISHING
           ------------------------------------------------- */
        const credentialPatterns = [
            "password",
            "username",
            "login",
            "log in",
            "otp",
            "one time password",
            "verification code",
            "verify your account",
            "confirm your identity",
            "security verification",
            "reset your credentials",
            "sign in to verify"
        ];
        const credentialMatches = findMatches(lower, credentialPatterns);

        if (credentialMatches.length > 0) {
            score += Math.min(25, credentialMatches.length * 8);
            reasons.push(`Credential or identity confirmation request detected: "${credentialMatches.slice(0, 3).join('", "')}"`);
            indicators.push("Credential request");
        }


        /* -------------------------------------------------
           F. BAIT / LURE LANGUAGE
           ------------------------------------------------- */
        const baitPatterns = [
            "congratulations",
            "winner",
            "prize",
            "lottery",
            "reward",
            "free gift",
            "job offer",
            "internship offer",
            "work from home",
            "selected for internship",
            "you have won",
            "claim your prize"
        ];
        const baitMatches = findMatches(lower, baitPatterns);

        if (baitMatches.length > 0) {
            score += Math.min(20, baitMatches.length * 7);
            reasons.push(`Bait or reward incentive language detected: "${baitMatches.slice(0, 3).join('", "')}"`);
            indicators.push("Bait / lure language");
        }


        /* -------------------------------------------------
           G. ATTACHMENT EXTRACTION & INSPECTION
           ------------------------------------------------- */
        const dangerousExtensions = [
            ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js",
            ".jar", ".msi", ".dll", ".docm", ".xlsm", ".iso"
        ];

        const attachments = extractAttachments(content);

        // Check extracted attachments
        const dangerousAttachments = [];
        attachments.forEach(att => {
            const attLower = att.toLowerCase();
            if (dangerousExtensions.some(ext => attLower.endsWith(ext))) {
                dangerousAttachments.push(att);
            }
        });

        // Also check if uploaded file itself has a dangerous/double extension
        dangerousExtensions.forEach(ext => {
            if (lowerFileName.endsWith(ext) || lowerFileName.includes(ext + ".")) {
                dangerousAttachments.push(fileName);
            }
        });

        if (dangerousAttachments.length > 0) {
            score += 35;
            const uniqueDangerous = uniqueArray(dangerousAttachments);
            reasons.push(`High-risk executable/macro attachment detected: "${uniqueDangerous.join('", "')}"`);
            indicators.push("Dangerous attachment");
        } else if (attachments.length > 0) {
            indicators.push(`${attachments.length} safe attachment(s)`);
        }


        /* -------------------------------------------------
           H. MSG FORMAT LIMITATION HANDLING
           ------------------------------------------------- */
        if (lowerFileName.endsWith(".msg")) {
            indicators.push("MSG partial inspection");
            if (!content || content.length < 50) {
                reasons.push("Proprietary Outlook .MSG binary container: Preliminary filename/header inspection applied. Full MAPI parsing requires backend API.");
            }
        }


        /* -------------------------------------------------
           I. SCORE CLAMPING & CLASSIFICATION
           ------------------------------------------------- */
        score = Math.max(0, Math.min(100, score));

        let risk;
        let riskClass;

        if (score >= 60) {
            risk = "High Risk";
            riskClass = "high";
        } else if (score >= 30) {
            risk = "Suspicious";
            riskClass = "suspicious";
        } else {
            risk = "Safe";
            riskClass = "safe";
        }

        // Clean default safe explanations
        if (reasons.length === 0) {
            reasons.push("No known phishing domains, URL shorteners, or malicious indicators were found.");
            reasons.push("Sender identity and message headers conform to standard correspondence norms.");
            indicators.push("Clean headers");
            indicators.push("No threat patterns");
        }

        return {
            id: generateID(),
            fileName: fileName,
            risk: risk,
            riskClass: riskClass,
            score: score,
            reasons: uniqueArray(reasons),
            indicators: uniqueArray(indicators),
            sender: sender || "Not detected",
            replyTo: replyTo || "Not detected",
            urls: urls.length,
            suspiciousUrls: suspiciousUrls.length,
            attachments: attachments,
            timestamp: new Date().toISOString(),
            recommendation: getRecommendation(riskClass)
        };
    }


    /* =====================================================
       8. RESULT RENDERING
       ===================================================== */

    function renderResult(result) {
        if (!result) return;

        // Filename & Risk Headings
        if (resultFile) resultFile.textContent = result.fileName;

        if (resultCard) {
            resultCard.classList.remove("risk-high", "risk-suspicious", "risk-safe");
            resultCard.classList.add("risk-" + result.riskClass);
        }

        if (resultIcon) {
            resultIcon.textContent = result.riskClass === "safe" ? "✓" : "!";
        }

        if (resultLabel) {
            if (result.riskClass === "high") {
                resultLabel.textContent = "THREAT DETECTED";
            } else if (result.riskClass === "suspicious") {
                resultLabel.textContent = "SUSPICIOUS ACTIVITY";
            } else {
                resultLabel.textContent = "SAFE EMAIL";
            }
        }

        if (resultHeading) {
            resultHeading.textContent = result.riskClass === "safe" ? "Safe" : result.risk + "!";
        }

        // Risk Score
        if (riskScoreLabel) {
            riskScoreLabel.textContent = `Risk Score: ${result.score}/100`;
        }

        if (riskScoreFill) {
            // Slight delay for smooth animated bar fill
            riskScoreFill.style.width = "0%";
            setTimeout(() => {
                riskScoreFill.style.width = result.score + "%";
            }, 60);
        }

        // Reasons List
        if (explanationList) {
            explanationList.innerHTML = "";
            result.reasons.forEach(reason => {
                const li = document.createElement("li");
                li.textContent = reason;
                explanationList.appendChild(li);
            });
        }

        // Indicators Badges
        if (indicatorsList) {
            indicatorsList.innerHTML = "";
            result.indicators.forEach(ind => {
                const span = document.createElement("span");
                span.className = `indicator-badge ${result.riskClass}`;
                span.textContent = ind;
                indicatorsList.appendChild(span);
            });
        }

        // Technical Information & Recommendation
        if (technicalResultInfo) {
            technicalResultInfo.innerHTML = `
                <h3>Analysis Details</h3>
                <p><strong>Sender:</strong> ${escapeHTML(result.sender)}</p>
                <p><strong>Reply-To:</strong> ${escapeHTML(result.replyTo)}</p>
                <p><strong>Links found:</strong> ${result.urls} (${result.suspiciousUrls} suspicious)</p>
                <p><strong>Attachments:</strong> ${result.attachments.length ? escapeHTML(result.attachments.join(", ")) : "None detected"}</p>
                <p class="js-recommendation">
                    <strong>Recommendation:</strong> ${escapeHTML(result.recommendation)}
                </p>
            `;
        }
    }


    /* =====================================================
       9. DOWNLOAD THREAT REPORT
       ===================================================== */

    if (downloadReportButton) {
        downloadReportButton.addEventListener("click", () => {
            downloadReport(state.currentResult);
        });
    }

    function downloadReport(result) {
        if (!result) {
            showToast("No scan result available to download");
            return;
        }

        const dateFormatted = formatDate(result.timestamp);
        const attachmentStr = result.attachments.length > 0 ? result.attachments.join(", ") : "None";

        const reportText = [
            "=================================================================",
            "MAIL HUNT",
            "AI EMAIL THREAT DETECTION REPORT",
            "=================================================================",
            "",
            `File Name:          ${result.fileName}`,
            `Risk Level:         ${result.risk}`,
            `Risk Score:         ${result.score}/100`,
            `Date/Time:          ${dateFormatted}`,
            `Sender:             ${result.sender}`,
            `Reply-To:           ${result.replyTo}`,
            "",
            "-----------------------------------------------------------------",
            "THREAT INDICATORS",
            "-----------------------------------------------------------------",
            ...result.indicators.map(ind => `- ${ind}`),
            "",
            "-----------------------------------------------------------------",
            "REASONS FOR DETECTION",
            "-----------------------------------------------------------------",
            ...result.reasons.map(r => `- ${r}`),
            "",
            "-----------------------------------------------------------------",
            "TECHNICAL SUMMARY",
            "-----------------------------------------------------------------",
            `Links Detected:     ${result.urls}`,
            `Suspicious Links:   ${result.suspiciousUrls}`,
            `Attachments:        ${attachmentStr}`,
            "",
            "-----------------------------------------------------------------",
            "RECOMMENDATION",
            "-----------------------------------------------------------------",
            result.recommendation,
            "",
            "=================================================================",
            "Generated by Mail Hunt Prototype Engine",
            "AI Email Threat Detection"
        ].join("\n");

        const blob = new Blob([reportText], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `MailHunt_Report_${sanitizeFileName(result.fileName)}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast("Threat report downloaded successfully");
    }


    /* =====================================================
       10. SCAN HISTORY & STORAGE
       ===================================================== */

    function saveScan(result) {
        const record = {
            id: result.id,
            fileName: result.fileName,
            risk: result.risk,
            riskClass: result.riskClass,
            riskScore: result.score,
            timestamp: result.timestamp,
            result: result
        };

        state.history.unshift(record);
        state.history = state.history.slice(0, 50); // Cap at 50

        // Increment stats
        state.stats.scanned++;
        if (result.riskClass === "high") {
            state.stats.high++;
            state.stats.threats++;
        } else if (result.riskClass === "suspicious") {
            state.stats.suspicious++;
            state.stats.threats++;
        } else {
            state.stats.safe++;
        }

        localStorage.setItem(STORAGE.history, JSON.stringify(state.history));
        localStorage.setItem(STORAGE.stats, JSON.stringify(state.stats));

        renderHistory();
        updateReports();
    }

    function renderHistory() {
        if (!historyList) return;

        historyList.innerHTML = "";

        if (state.history.length === 0) {
            historyList.innerHTML = `
                <div class="history-item">
                    <span class="risk-dot" style="background: var(--muted);"></span>
                    <div>
                        <strong>No scans yet</strong>
                        <p>Upload an email to start analyzing threats.</p>
                    </div>
                </div>
            `;
            if (clearHistoryButton) clearHistoryButton.style.display = "none";
            return;
        }

        if (clearHistoryButton) clearHistoryButton.style.display = "block";

        state.history.forEach(item => {
            const historyItem = document.createElement("div");
            historyItem.className = `history-item ${item.riskClass || "safe"}`;

            const dateStr = formatDate(item.timestamp);

            historyItem.innerHTML = `
                <span class="risk-dot"></span>
                <div>
                    <strong>${escapeHTML(item.fileName)}</strong>
                    <p>${escapeHTML(item.risk)} · ${escapeHTML(dateStr)} · Score ${item.riskScore}/100</p>
                </div>
                <button
                    type="button"
                    class="view-button"
                    data-screen="result"
                    data-history-id="${item.id}"
                >
                    View
                </button>
            `;

            historyList.appendChild(historyItem);
        });
    }

    if (clearHistoryButton) {
        clearHistoryButton.addEventListener("click", () => {
            if (state.history.length === 0) {
                showToast("History is already empty");
                return;
            }

            const confirmed = confirm("Are you sure you want to clear your entire scan history?");
            if (!confirmed) return;

            state.history = [];
            localStorage.setItem(STORAGE.history, JSON.stringify([]));

            renderHistory();
            updateReports();
            showToast("Scan history cleared");
        });
    }

    function initializeSampleHistory() {
        if (state.history.length > 0) return;

        state.history = [
            {
                id: "sample-high",
                fileName: "suspicious_email.eml",
                risk: "High Risk",
                riskClass: "high",
                riskScore: 86,
                timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
                result: {
                    id: "sample-high",
                    fileName: "suspicious_email.eml",
                    risk: "High Risk",
                    riskClass: "high",
                    score: 86,
                    reasons: [
                        "Sender uses a domain extension frequently abused in phishing: alerts@suspicious-bank-login.xyz",
                        "Sender domain does not match Reply-To domain",
                        "High-pressure/urgent phrasing detected: \"urgent\", \"account suspended\"",
                        "Credential or identity confirmation request detected: \"verify your account\""
                    ],
                    indicators: [
                        "Suspicious domain TLD",
                        "Sender & Reply-To domain mismatch",
                        "Urgent / pressure language",
                        "Credential request"
                    ],
                    sender: "alerts@suspicious-bank-login.xyz",
                    replyTo: "support-desk@gmail.com",
                    urls: 2,
                    suspiciousUrls: 1,
                    attachments: [],
                    timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
                    recommendation: getRecommendation("high")
                }
            },
            {
                id: "sample-suspicious",
                fileName: "prize_winner.eml",
                risk: "Suspicious",
                riskClass: "suspicious",
                riskScore: 42,
                timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
                result: {
                    id: "sample-suspicious",
                    fileName: "prize_winner.eml",
                    risk: "Suspicious",
                    riskClass: "suspicious",
                    score: 42,
                    reasons: [
                        "Bait or reward incentive language detected: \"congratulations\", \"winner\", \"prize\"",
                        "1 suspicious link(s) detected (e.g. shorteners, IP hosts, or credential patterns)"
                    ],
                    indicators: [
                        "Bait / lure language",
                        "Suspicious link(s)"
                    ],
                    sender: "winner-notice@rewards-claim.org",
                    replyTo: "winner-notice@rewards-claim.org",
                    urls: 1,
                    suspiciousUrls: 1,
                    attachments: [],
                    timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
                    recommendation: getRecommendation("suspicious")
                }
            },
            {
                id: "sample-safe",
                fileName: "meeting_invite.eml",
                risk: "Safe",
                riskClass: "safe",
                riskScore: 8,
                timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
                result: {
                    id: "sample-safe",
                    fileName: "meeting_invite.eml",
                    risk: "Safe",
                    riskClass: "safe",
                    score: 8,
                    reasons: [
                        "No known phishing domains, URL shorteners, or malicious indicators were found.",
                        "Sender identity and message headers conform to standard correspondence norms."
                    ],
                    indicators: [
                        "Clean headers",
                        "No threat patterns"
                    ],
                    sender: "calendar@corporate-company.com",
                    replyTo: "calendar@corporate-company.com",
                    urls: 0,
                    suspiciousUrls: 0,
                    attachments: [],
                    timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
                    recommendation: getRecommendation("safe")
                }
            }
        ];

        localStorage.setItem(STORAGE.history, JSON.stringify(state.history));
    }


    /* =====================================================
       11. THREAT REPORTS & VISUALIZATION
       ===================================================== */

    function updateReports() {
        if (emailsScanned) emailsScanned.textContent = state.stats.scanned;
        if (threatsDetected) threatsDetected.textContent = state.stats.threats;
        if (statHigh) statHigh.textContent = state.stats.high;
        if (statSuspicious) statSuspicious.textContent = state.stats.suspicious;
        if (statSafe) statSafe.textContent = state.stats.safe;

        renderRiskDistribution();
        renderRecentThreats();
    }

    function renderRiskDistribution() {
        if (!riskChart) return;

        const total = state.stats.high + state.stats.suspicious + state.stats.safe;
        const calcPercent = val => (total > 0 ? Math.round((val / total) * 100) : 0);

        const highPct = calcPercent(state.stats.high);
        const suspPct = calcPercent(state.stats.suspicious);
        const safePct = calcPercent(state.stats.safe);

        riskChart.innerHTML = `
            <h4>Risk Distribution</h4>
            <div class="js-chart-row">
                <span>High Risk</span>
                <div class="js-chart-bar">
                    <div class="bar-high" style="width: ${highPct}%;"></div>
                </div>
                <strong>${highPct}%</strong>
            </div>
            <div class="js-chart-row">
                <span>Suspicious</span>
                <div class="js-chart-bar">
                    <div class="bar-suspicious" style="width: ${suspPct}%;"></div>
                </div>
                <strong>${suspPct}%</strong>
            </div>
            <div class="js-chart-row">
                <span>Safe</span>
                <div class="js-chart-bar">
                    <div class="bar-safe" style="width: ${safePct}%;"></div>
                </div>
                <strong>${safePct}%</strong>
            </div>
        `;
    }

    function renderRecentThreats() {
        if (!recentThreatsList) return;

        const threats = state.history
            .filter(item => item.riskClass === "high" || item.riskClass === "suspicious")
            .slice(0, 4);

        if (threats.length === 0) {
            recentThreatsList.innerHTML = `
                <div class="risk-row">
                    <span>🟢 No recent threats recorded</span>
                    <strong>All clear</strong>
                </div>
            `;
            return;
        }

        recentThreatsList.innerHTML = threats.map(item => {
            const icon = item.riskClass === "high" ? "🔴" : "🟡";
            return `
                <div class="risk-row">
                    <span>${icon} ${escapeHTML(item.fileName)}</span>
                    <strong>${escapeHTML(item.risk)}</strong>
                </div>
            `;
        }).join("");
    }


    /* =====================================================
       12. SETTINGS & THEME
       ===================================================== */

    function renderSettings() {
        updateAccountEmail();

        if (settingAlerts) settingAlerts.checked = !!state.settings.alerts;
        if (settingAutoScan) settingAutoScan.checked = !!state.settings.autoScan;
        if (settingLinkWarnings) settingLinkWarnings.checked = !!state.settings.linkWarnings;
        if (settingLanguage) settingLanguage.value = state.settings.language || "English";
        if (themeSelect) themeSelect.value = state.settings.theme || "light";
    }

    function saveSettings() {
        localStorage.setItem(STORAGE.settings, JSON.stringify(state.settings));
    }

    if (settingAlerts) {
        settingAlerts.addEventListener("change", () => {
            state.settings.alerts = settingAlerts.checked;
            saveSettings();
            showToast(`Threat Alerts: ${settingAlerts.checked ? "ON" : "OFF"}`);
        });
    }

    if (settingAutoScan) {
        settingAutoScan.addEventListener("change", () => {
            state.settings.autoScan = settingAutoScan.checked;
            saveSettings();
            showToast(`Auto-Scan Emails: ${settingAutoScan.checked ? "ON" : "OFF"}`);
        });
    }

    if (settingLinkWarnings) {
        settingLinkWarnings.addEventListener("change", () => {
            state.settings.linkWarnings = settingLinkWarnings.checked;
            saveSettings();
            showToast(`Link Warnings: ${settingLinkWarnings.checked ? "ON" : "OFF"}`);
        });
    }

    if (settingLanguage) {
        settingLanguage.addEventListener("change", () => {
            state.settings.language = settingLanguage.value;
            saveSettings();
            showToast(`Language set to ${settingLanguage.value}`);
        });
    }

    if (themeSelect) {
        themeSelect.addEventListener("change", () => {
            const newTheme = themeSelect.value;
            state.settings.theme = newTheme;
            saveSettings();
            applyTheme(newTheme);
            showToast(`${newTheme === "dark" ? "Dark" : "Light"} theme applied`);
        });
    }

    function applyTheme(theme) {
        const isDark = theme === "dark";
        document.body.classList.toggle("dark-theme", isDark);
    }

    function updateAccountEmail() {
        if (!accountEmail) return;
        accountEmail.textContent = state.user ? state.user.email : "Not signed in";
    }


    /* =====================================================
       13. UTILITY & HELPER FUNCTIONS
       ===================================================== */

    function isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }

    function wait(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function generateID() {
        return Date.now().toString(36) + Math.random().toString(36).substring(2, 7);
    }

    function escapeHTML(str) {
        if (!str) return "";
        return String(str)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function sanitizeFileName(name) {
        return String(name || "email").replace(/[^a-z0-9._-]/gi, "_");
    }

    function uniqueArray(arr) {
        return Array.from(new Set(arr));
    }

    function formatDate(isoDate) {
        if (!isoDate) return "Recent";
        try {
            const date = new Date(isoDate);
            return date.toLocaleString([], {
                month: "short",
                day: "numeric",
                hour: "numeric",
                minute: "2-digit"
            });
        } catch (e) {
            return String(isoDate);
        }
    }

    function getHeader(content, headerName) {
        const regex = new RegExp("^" + headerName + "\\s*:\\s*(.+)$", "im");
        const match = content.match(regex);
        return match ? match[1].trim() : "";
    }

    function extractEmailAddress(str) {
        if (!str) return "";
        const match = str.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        return match ? match[0].toLowerCase() : "";
    }

    function extractURLs(text) {
        const regex = /https?:\/\/[^\s<>"')]+/gi;
        return text.match(regex) || [];
    }

    function isSuspiciousURL(url) {
        const lower = url.toLowerCase();
        const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"];
        if (shorteners.some(s => lower.includes(s))) return true;

        const suspiciousKeywords = ["login", "verify", "account", "secure", "payment", "update", "banking", "credential", "signin", "auth", "confirm"];
        if (suspiciousKeywords.some(kw => lower.includes(kw))) return true;

        if (lower.includes("xn--")) return true;

        try {
            const hostname = new URL(url).hostname;
            if (looksLikeIPAddress(hostname)) return true;
        } catch (e) {
            // Malformed URL
            return true;
        }

        return false;
    }

    function looksLikeIPAddress(val) {
        return /^\d{1,3}(\.\d{1,3}){3}$/.test(val);
    }

    function findMatches(text, words) {
        return words.filter(w => text.includes(w));
    }

    function extractAttachments(content) {
        const filenames = [];

        // MIME Content-Disposition filename
        const dispRegex = /filename\s*=\s*["']?([^"'\s;>\r\n]+)/gi;
        let match;
        while ((match = dispRegex.exec(content)) !== null) {
            if (match[1]) filenames.push(match[1].trim());
        }

        // MIME Content-Type name
        const nameRegex = /name\s*=\s*["']?([^"'\s;>\r\n]+)/gi;
        while ((match = nameRegex.exec(content)) !== null) {
            if (match[1]) filenames.push(match[1].trim());
        }

        return uniqueArray(filenames);
    }

    function getRecommendation(riskClass) {
        if (riskClass === "high") {
            return "Do not click links, open attachments, or reply to this sender. Quarantine or delete this email immediately and report it to your organization's security administrator.";
        }
        if (riskClass === "suspicious") {
            return "Exercise caution. Confirm the sender's identity through an independent, trusted channel before following links or downloading attachments.";
        }
        return "No significant threats were detected. Maintain general security hygiene and verify unexpected requests.";
    }


    /* =====================================================
       14. TOAST NOTIFICATIONS
       ===================================================== */

    let toastTimeout = null;

    function showToast(message) {
        if (!toast) return;
        clearTimeout(toastTimeout);
        toast.textContent = message;
        toast.classList.add("show");
        toastTimeout = setTimeout(() => {
            toast.classList.remove("show");
        }, 2500);
    }


    /* =====================================================
       15. APP BOOTSTRAP
       ===================================================== */

    initializeSampleHistory();
    applyTheme(state.settings.theme);
    updateAccountEmail();
    renderHistory();
    updateReports();
    renderSettings();

    // Show initial screen: if user is logged in, show upload, otherwise login
    if (state.user && state.user.email) {
        showScreen("upload");
    } else {
        showScreen("login");
    }
});