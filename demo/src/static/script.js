/////////////////////////////////////
// extract functions from simpleWebAuthn
/////////////////////////////////////
const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

/////////////////////////////////////
// helper functions for html display
/////////////////////////////////////
function timestampMessage(message) {
    const now = Date.now();
    const formattedTime = new Date(now).toLocaleTimeString([], { hour12: false });
    const formattedMilliseconds = (new Date(now) % 1000).toString().padStart(3, '0');
    return `${formattedTime}.${formattedMilliseconds}: ${message}`;
}

function setStatusMessage(message) {
    const statusDiv = document.getElementById('status');
    statusDiv.innerText = message + `\n`;
}

function appendStatusMessage(message) {
    const statusDiv = document.getElementById('status');
    statusDiv.innerText += message + `\n`;
}

function setInnerHTMLById(Id,msg) {
    const elementObj = document.getElementById(Id);
    elementObj.innerHTML = msg;
}

async function registerUser() {
    const username = document.getElementById('username').value;

    setInnerHTMLById('reg-options','');
    setInnerHTMLById('reg-result','');
    setInnerHTMLById('reg-ver-result','');
    setInnerHTMLById('auth-options','');
    setInnerHTMLById('auth-result','');
    setInnerHTMLById('auth-ver-result','');

    if (!username) {
        setStatusMessage('username cannot be empty');
        return;
    }
    const formData = new FormData(); // Create FormData object
    formData.append("username", username);
    const resp = await fetch("/register", {
        method: "POST",
        body: formData
    });

    // generate options using python webAuthn module
    // options is used by simpleWebAuthn browser for client passkey generation
    setStatusMessage(timestampMessage('sent a POST request with username'));
    const opts = await resp.json();
    appendStatusMessage(timestampMessage('received generated options from server'));

    setInnerHTMLById('reg-options',`<pre>${JSON.stringify(opts, null, 2)}</pre>`);

    // Start passkey creation using simplewebauthn@browser
    let regResp;
    try {
        appendStatusMessage(timestampMessage("calling startRegistration on client side"));
        regResp = await startRegistration(opts);
        appendStatusMessage(timestampMessage("startRegistration completed on client side"));
        setInnerHTMLById('reg-result',`<pre>${JSON.stringify(regResp, null, 2)}</pre>`);
    } catch (err) {
        appendStatusMessage(timestampMessage(err));
        throw new Error(err);
    }

    // create a new json to pass to webauthn for verification
    // the username is added to the payload
    // the payload will be splitted in on the server
    const payload = {
        username: username,
        original_json: JSON.stringify(regResp)
    };

    appendStatusMessage(timestampMessage("calling verify_registration_response"));
    // use verify_authentication_response function in webauthn to verify
    // public key is correct
    // use webauthn.helpers.structs to find the public key
    const verificationResp = await fetch(
        "/verify-registration",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        }
    );
    appendStatusMessage(timestampMessage('received verify_registration_response'));
    // Report validation response
    const verificationRespJSON = await verificationResp.json();
    const { verified, msg } = verificationRespJSON;

    setInnerHTMLById('reg-ver-result',`<pre>${JSON.stringify(verificationRespJSON, null, 2)}</pre>`);
    if (verified) {
        appendStatusMessage('verified sucessfully. User added server side');
    } else {
        appendStatusMessage(msg);
    }
}

async function authenticateUser() {
    const username = document.getElementById('username').value; // Assuming you have an input field with ID 'username'

    setInnerHTMLById('auth-options','');
    setInnerHTMLById('auth-result','');
    setInnerHTMLById('auth-ver-result','');

    if (!username) {
        setStatusMessage('username cannot be empty');
        return;
    }
    const formData = new FormData(); // Create FormData object
    formData.append("username", username);
    const resp = await fetch("/authenticate", {
        method: "POST",
        body: formData
    });

    setStatusMessage(timestampMessage('sent a POST request with username'));
    const opts = await resp.json();
    appendStatusMessage(timestampMessage('received generated options from server'));

    // Display the JSON message in the auth-options div
    setInnerHTMLById('auth-options',`<pre>${JSON.stringify(opts, null, 2)}</pre>`);

    // Start WebAuthn Authentication
    let authResp;
    try {
        appendStatusMessage(timestampMessage("calling startAuthentication on client side"));
        authResp = await startAuthentication(opts);
        appendStatusMessage(timestampMessage("startAuthentication completed on client side"));
        setInnerHTMLById('auth-result',`<pre>${JSON.stringify(authResp, null, 2)}</pre>`);
    } catch (err) {
        appendStatusMessage(timestampMessage(err));
        throw new Error(err);
    }

    // create a new json to pass to webauthn for verification
    // the username is added to the payload
    // the payload will be splitted in on the server
    const payload = {
        username: username,
        original_json: JSON.stringify(authResp)
    };

    appendStatusMessage(timestampMessage("calling verify_authentication_response"));
    const verificationResp = await fetch(
        "/verify-authentication",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        }
    );
    appendStatusMessage(timestampMessage('received verify_authentication_response'));
    // Report validation response
    const verificationRespJSON = await verificationResp.json();
    const { verified, msg } = verificationRespJSON;

    setInnerHTMLById('auth-ver-result',`<pre>${JSON.stringify(verificationRespJSON, null, 2)}</pre>`);

    if (verified) {
        appendStatusMessage('authentication verified sucessfully.');
    } else {
        appendStatusMessage(msg);
    }
}
