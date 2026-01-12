import { initAccessibility } from './a11y.js';

/**
 * CRSF token for requests.
 */
let csrfToken = '';
let discreetLogin = false;
let user = null;

/**
 * Gets a CSRF token from the server.
 * @returns {Promise<string>} CSRF token
 */
async function getCsrfToken() {
    const response = await fetch('/csrf-token');
    const data = await response.json();
    return data.token;
}

/**
 * Gets a list of users from the server.
 * @returns {Promise<object>} List of users
 */
async function getUserList() {
    const response = await fetch('/api/users/list', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
        },
    });

    if (!response.ok) {
        const errorData = await response.json();
        return displayError(errorData.error || 'An error occurred');
    }

    if (response.status === 204) {
        discreetLogin = true;
        return [];
    }

    const userListObj = await response.json();
    console.log(userListObj);
    return userListObj;
}

/**
 * Requests a recovery code for the user.
 * @param {string} handle User handle
 * @returns {Promise<void>}
 */
async function sendRecoveryPart1(handle) {
    const response = await fetch('/api/users/recover-step1', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ handle }),
    });

    if (!response.ok) {
        const errorData = await response.json();
        return displayError(errorData.error || 'An error occurred');
    }

    showRecoveryBlock();
}

/**
 * Sets a new password for the user using the recovery code.
 * @param {string} handle User handle
 * @param {string} code Recovery code
 * @param {string} newPassword New password
 * @returns {Promise<void>}
 */
async function sendRecoveryPart2(handle, code, newPassword) {
    const recoveryData = {
        handle,
        code,
        newPassword,
    };

    const response = await fetch('/api/users/recover-step2', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify(recoveryData),
    });

    if (!response.ok) {
        const errorData = await response.json();
        return displayError(errorData.error || 'An error occurred');
    }

    console.log(`Successfully recovered password for ${handle}!`);
    await performLogin(handle, newPassword);
}

/**
 * Attempts to log in the user.
 * @param {string} handle User's handle
 * @param {string} password User's password
 * @param {string|null} token Turnstile token
 * @returns {Promise<void>}
 */
async function performLogin(handle, password, token = null) {
    const userInfo = {
        handle: handle,
        password: password,
        turnstileToken: token,
    };

    try {
        const response = await fetch('/api/users/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken,
            },
            body: JSON.stringify(userInfo),
        });

        if (!response.ok) {
            const errorData = await response.json();
            return displayError(errorData.error || 'An error occurred');
        }

        const data = await response.json();

        if (data.handle) {
            console.log(`Successfully logged in as ${handle}!`);
            redirectToHome();
        }
    } catch (error) {
        console.error('Error logging in:', error);
        displayError(String(error));
    }
}

// --- Turnstile Logic ---
window['turnstileWidgetId'] = null;

/**
 * Opens Turnstile modal and executes callback on success.
 * @param {function(string): Promise<void>} allowedAction Action to perform with the token
 * @param {function(): void} [onCleanup] Function to call when processing is finished (success or failure)
 */
async function openTurnstile(allowedAction, onCleanup) {
    if (!window['turnstileEnabled']) {
        await allowedAction(null);
        if (onCleanup) onCleanup();
        return;
    }

    // Basic validation passed, clear previous errors
    displayError('');
    $('#turnstileModal').show();

    // Render if not already rendered
    if (window['turnstileWidgetId'] === null && window['turnstile']) {
        window['turnstileWidgetId'] = window['turnstile'].render('#turnstileWidget', {
            sitekey: window['turnstileSiteKey'],
            callback: async function (token) {
                $('#turnstileModal').hide();
                try {
                    await allowedAction(token);
                } catch (e) {
                    console.error(e);
                } finally {
                    window['turnstile'].reset(window['turnstileWidgetId']);
                    if (onCleanup) onCleanup();
                }
            },
            'error-callback': function () {
                displayError('Turnstile verification error. Please try again.');
                $('#turnstileModal').hide();
                window['turnstile'].reset(window['turnstileWidgetId']);
                if (onCleanup) onCleanup();
            }
        });
    } else if (window['turnstileWidgetId'] !== null) {
        window['turnstile'].reset(window['turnstileWidgetId']);
    }
}

// Wrapped Actions
async function triggerLogin() {
    let handle = '';
    const password = String($('#userPassword').val());

    if (discreetLogin) {
        handle = String($('#userHandle').val());
    } else {
        handle = user ? user.handle : '';
    }

    if (!handle && !discreetLogin) {
        return displayError('Please select a user.');
    }

    if (!handle && discreetLogin) {
        return displayError('Please enter a user handle.');
    }

    if (!password) {
        return displayError('Please enter your password.');
    }

    const $btn = $('#loginButton');
    const originalText = $btn.text();
    $btn.text('Logging in...').addClass('disabled').css('pointer-events', 'none');

    const cleanup = () => {
        $btn.text(originalText).removeClass('disabled').css('pointer-events', '');
    };

    await openTurnstile(async (token) => {
        await performLogin(handle, password, token);
    }, cleanup);
}

async function triggerSignup() {
    const userId = String($('#signupUserId').val());
    const orderId = String($('#signupOrderId').val());
    const name = String($('#signupName').val());
    const password = String($('#signupPassword').val());

    if (!userId || !orderId || !name || !password) {
        return displayError('Please fill in all fields.');
    }

    const $btn = $('#doSignupButton');
    const originalText = $btn.text();
    $btn.text('Signing up...').addClass('disabled').css('pointer-events', 'none');

    const cleanup = () => {
        $btn.text(originalText).removeClass('disabled').css('pointer-events', '');
    };

    await openTurnstile(async (token) => {
        await performSignup(userId, orderId, name, password, token);
    }, cleanup);
}

/**
 * Handles the user selection event.
 * @param {object} selectedUser User object
 * @returns {Promise<void>}
 */
async function onUserSelected(selectedUser) {
    console.log('User selected:', selectedUser);

    const userBlock = $(`.userSelect[data-handle="${selectedUser.handle}"]`);

    $('#passwordRecoveryBlock').hide();
    $('#signupBlock').hide();
    $('#passwordEntryBlock').show();

    // Login Handler is already bound to triggerLogin globally.
    // triggerLogin will use the global `user` variable which we just updated.

    displayError('');
}

/**
 * Attempts to sign up a new user.
 * @param {string} userId Afdian User ID
 * @param {string} orderId Afdian Order ID
 * @param {string} name Nickname
 * @param {string} password Password
 * @param {string|null} token Turnstile token
 * @returns {Promise<void>}
 */
async function performSignup(userId, orderId, name, password, token = null) {
    if (!userId || !orderId || !name || !password) {
        return displayError('Please fill in all fields');
    }

    try {
        const response = await fetch('/api/users/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken,
            },
            body: JSON.stringify({ userId, orderId, name, password, turnstileToken: token }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            return displayError(errorData.error || 'Signup failed');
        }

        const data = await response.json();
        console.log(`Successfully signed up as ${data.handle}!`);

        // Auto-login after signup
        await performLogin(data.handle, password);

    } catch (error) {
        console.error('Error signing up:', error);
        displayError('An error occurred during signup');
    }

    displayError('');
}

/**
 * Displays an error message to the user.
 * @param {string} message Error message
 */
function displayError(message) {
    $('#errorMessage').text(message);
}

/**
 * Redirects the user to the home page.
 * Preserves the query string.
 */
function redirectToHome() {
    // Create a URL object based on the current location
    const currentUrl = new URL(window.location.href);

    // After a login there's no need to preserve the
    // noauto parameter (if present)
    currentUrl.searchParams.delete('noauto');

    // Set the pathname to root and keep the updated query string
    currentUrl.pathname = '/';

    // Redirect to the new URL
    window.location.href = currentUrl.toString();
}

/**
 * Hides the password entry block and shows the password recovery block.
 */
function showRecoveryBlock() {
    $('#passwordEntryBlock').hide();
    $('#passwordRecoveryBlock').show();
    displayError('');
}

/**
 * Hides the password recovery block and shows the password entry block.
 */
function onCancelRecoveryClick() {
    $('#passwordRecoveryBlock').hide();
    $('#passwordEntryBlock').show();
    displayError('');
}

/**
 * Configures the login page for normal login.
 * @param {import('../../src/users').UserViewModel[]} userList List of users
 */
function configureNormalLogin(userList) {
    console.log('Discreet login is disabled');
    $('#handleEntryBlock').hide();
    // $('#normalLoginPrompt').show();
    // $('#discreetLoginPrompt').hide();
    console.log(userList);
    for (const user of userList) {
        const userBlock = $('<div></div>').addClass('userSelect');
        const avatarBlock = $('<div></div>').addClass('avatar');
        avatarBlock.append($('<img>').attr('src', user.avatar));
        userBlock.append(avatarBlock);
        userBlock.append($('<span></span>').addClass('userName').text(user.name));
        userBlock.append($('<small></small>').addClass('userHandle').text(user.handle));
        userBlock.on('click', () => onUserSelected(user));
        $('#userList').append(userBlock);
    }
}

/**
 * Configures the login page for discreet login.
 */
function configureDiscreetLogin() {
    console.log('Discreet login is enabled');
    $('#handleEntryBlock').show();
    // $('#normalLoginPrompt').hide();
    // $('#discreetLoginPrompt').show();
    $('#userList').hide();
    $('#passwordRecoveryBlock').hide();
    $('#passwordEntryBlock').show();

    // Login Handler is already bound to triggerLogin globally.
    // triggerLogin handles discreet mode.

    $('#recoverPassword').off('click').on('click', async () => {
        const handle = String($('#userHandle').val());
        await sendRecoveryPart1(handle);
    });

    $('#sendRecovery').off('click').on('click', async () => {
        const handle = String($('#userHandle').val());
        const code = String($('#recoveryCode').val());
        const newPassword = String($('#newPassword').val());
        await sendRecoveryPart2(handle, code, newPassword);
    });
}

(async function () {
    // Background image logic
    const updateBackgrounds = () => {
        // Body gets the wide image
        document.body.style.backgroundImage = `url('https://t.alcy.cc/ycy/')`;

        // Side panel gets the vertical image
        const visualPanel = document.querySelector('.login-visual');
        if (visualPanel instanceof HTMLElement) {
            visualPanel.style.backgroundImage = `url('https://t.alcy.cc/mp/')`;
        }
    };
    updateBackgrounds();

    // Global Event Listeners for Static UI Elements

    // Signup Navigation
    $('#showSignupButton').on('click', () => {
        $('#passwordEntryBlock').hide();
        $('#handleEntryBlock').hide();
        $('#userList').hide();
        $('#signupBlock').show();
        displayError('');
    });

    $('#cancelSignupButton').on('click', () => {
        $('#signupBlock').hide();
        $('#passwordEntryBlock').show();

        if (discreetLogin) {
            $('#handleEntryBlock').show();
        } else {
            $('#userList').show();
        }

        displayError('');
    });

    $('#doSignupButton').on('click', async () => {
        const userId = String($('#signupUserId').val());
        const orderId = String($('#signupOrderId').val());
        const name = String($('#signupName').val());
        const password = String($('#signupPassword').val());
        await performSignup(userId, orderId, name, password);
    });

    // Recovery Navigation
    $('#recoverPassword').on('click', async () => {
        $('#passwordEntryBlock').hide();
        $('#passwordRecoveryBlock').show();
        displayError('');
    });

    $('#cancelRecovery').on('click', () => {
        $('#passwordRecoveryBlock').hide();
        $('#passwordEntryBlock').show();
        displayError('');
    });

    // Check Turnstile configuration
    try {
        const turnstileConfig = await fetch('/api/users/turnstile-config').then(r => r.json());
        if (turnstileConfig.enabled) {
            window['turnstileEnabled'] = true;
            window['turnstileSiteKey'] = turnstileConfig.siteKey;
        }
    } catch (err) {
        console.error('Failed to load Turnstile config', err);
    }

    initAccessibility();

    // --- Turnstile Logic ---
    // Rebind Click Handlers to new Triggers
    $('#loginButton').off('click').on('click', triggerLogin);
    $('#doSignupButton').off('click').on('click', triggerSignup);

    csrfToken = await getCsrfToken();
    const userList = await getUserList();

    if (discreetLogin) {
        configureDiscreetLogin();
    } else {
        configureNormalLogin(userList);
    }
    document.getElementById('shadow_popup').style.opacity = '';
    $('#cancelRecovery').on('click', onCancelRecoveryClick);
    $(document).on('keydown', (evt) => {
        if (evt.key === 'Enter' && document.activeElement.tagName === 'INPUT') {
            if ($('#passwordRecoveryBlock').is(':visible')) {
                $('#sendRecovery').trigger('click');
            } else {
                $('#loginButton').trigger('click');
            }
        }
    });
})();
