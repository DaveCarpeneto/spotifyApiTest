$( document ).ready(function() {

    console.log( "ready!" );

    if (authenticated()) {

        liveItUp();

    } else if (expired()) {

        refreshToken();

    } else if (authCodeInUrl()) {

        authenticateWithCode();

    } else {

        presentLogin();

    }

});

// return true if the user auth is all good
function authenticated() {

    return getSessionToken() != null && sessionIsNotExpired();

}

// return true if the user auth is all good
function expired() {

    return getSessionToken() != null && !(sessionIsNotExpired());

}

// return true if it looks like we have auth codes in our URL
function authCodeInUrl() {

    const urlParams = new URLSearchParams(window.location.search);
    let code = urlParams.get('code');
    let state = urlParams.get('state');
    let error = urlParams.get('error');

    return error == null && code != null && state != null && state == getSessionState();

}

// TODO
function refreshToken() {

    if (getSessionRefreshToken() == null) {

        // TODO - error
        presentLogin();

    }

    $.ajax({

    async: false, 

    type: "POST",

    url: "https://accounts.spotify.com/api/token", 

    data: {
        'grant_type': 'refresh_token',
        'refresh_token': getSessionRefreshToken(),
        'client_id': '004b4a3922474b05bd21e17a25df5de0'
    },

    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },

    success: function(result, status, xhr){

        storeSessionToken(result['access_token']);
        storeSessionRefreshToken(result['refresh_token']);
        storeSessionExpiry(result['expires_in']);
        window.location.assign(location.protocol + '//' + location.host + location.pathname) // to strip out the credentials from the URL

    },

    error: function(result, status, xhr){

        console.error(result);

    }

    });

}

// returns true if we got an auth code in the URL
function authenticateWithCode() {

    const urlParams = new URLSearchParams(window.location.search);
    let code = urlParams.get('code');

$.ajax({

    async: false, 

    type: "POST",

    url: "https://accounts.spotify.com/api/token", 

    data: {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': 'https://davecarpeneto.github.io/spotifyApiTest',
        'client_id': '004b4a3922474b05bd21e17a25df5de0',
        'code_verifier': getSessionVerifier()
    },

    success: function(result, status, xhr){

        storeSessionToken(result['access_token']);
        storeSessionRefreshToken(result['refresh_token']);
        storeSessionExpiry(result['expires_in']);
        window.location.assign(location.protocol + '//' + location.host + location.pathname) // to strip out the credentials from the URL

    },

    error: function(result, status, xhr){

        console.error(result);

    }

});

}

// pop the login button up on the page
async function presentLogin() {

    // generate code_challenge & state 
    const codeVerifier  = generateRandomString(64);
    const hashed = await hashString(codeVerifier)
    const codeChallenge = base64encode(hashed);
    storeSessionState(codeChallenge);
    storeSessionVerifier(codeVerifier);
    storeSessionToken(null);
    storeSessionRefreshToken(null);
    storeSessionExpiry(null);

    // stuff we need to know about
    const clientId = '004b4a3922474b05bd21e17a25df5de0';
    const redirectUri = 'https://davecarpeneto.github.io/spotifyApiTest';
    const scope = 'playlist-read-private playlist-read-collaborative user-read-private user-read-email';
    const authUrl = new URL("https://accounts.spotify.com/authorize");

    const formHtml = `<form action=${authUrl}>
                <input type="hidden" id="client_id" name="client_id" value="${clientId}"/>
                <input type="hidden" id="response_type" name="response_type" value="code"/>
                <input type="hidden" id="redirect_uri" name="redirect_uri" value="${redirectUri}"/>
                <input type="hidden" id="state" name="state" value="${codeChallenge}"/>
                <input type="hidden" id="scope" name="scope" value="${scope}"/>
                <input type="hidden" id="code_challenge_method" name="code_challenge_method" value="S256"/>
                <input type="hidden" id="code_challenge" name="code_challenge" value="${codeChallenge}"/>
                <input type="submit" value="Login to Spotify"/>	
            </form>`;

    $("#main").html(formHtml);

}

// TODO:
function liveItUp() {

    $("#main").html("IT WORKS");

}

function storeSessionState(state) {

    if (state == null) {

        localStorage.removeItem("spotifyApiState");

    } else {

        localStorage.setItem("spotifyApiState", state);

    }

}

function getSessionState() {

    return localStorage.getItem("spotifyApiState");

}

function storeSessionVerifier(verifier) {

    if (verifier == null) {

        localStorage.removeItem("spotifyApiVerifier");

    } else {

        localStorage.setItem("spotifyApiVerifier", verifier);

    }

}

function getSessionVerifier() {

    return localStorage.getItem("spotifyApiVerifier");

}

function storeSessionToken(token) {

    if (token == null) {

        localStorage.removeItem("spotifyApiToken");

    } else {

        localStorage.setItem("spotifyApiToken", token);

    }

}

function getSessionToken() {

    return localStorage.getItem("spotifyApiToken");

}

function storeSessionRefreshToken(token) {

    if (token == null) {

        localStorage.removeItem("spotifyApiRefreshToken");

    } else {

        localStorage.setItem("spotifyApiRefreshToken", token);

    }

}

function getSessionRefreshToken() {

    return localStorage.getItem("spotifyApiRefreshToken");

}

function storeSessionExpiry(timeInSeconds) {

    if (timeInSeconds == null) {

        localStorage.removeItem("spotifyApiExpiry");

    } else {

        let timeInMilliseconds = (timeInSeconds * 1000) + (new Date).getTime();
        localStorage.setItem("spotifyApiExpiry", JSON.stringify(timeInMilliseconds));

    }

}

function sessionIsNotExpired() {

    let expiryTime = localStorage.getItem("spotifyApiExpiry");

    return expiryTime != null &&  JSON.parse(expiryTime) > (new Date).getTime();

}

function generateRandomString(length) {
    
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
   
}

function hashString(value) {

    const encoder = new TextEncoder()
    const data = encoder.encode(value)
    return window.crypto.subtle.digest('SHA-256', data)

}

function base64encode(value) {

    return btoa(String.fromCharCode(...new Uint8Array(value)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

}

