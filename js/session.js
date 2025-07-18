$( document ).ready(function() {

    console.log( "ready!" );

    if (checkForURLParams()) {
        
        window.location.assign("/") // to strip out the credentials from the URL

    }

    if (!isLoggedIn()) {

        presentLogin();

    } else {

        liveItUp();

    }

});

// returns true if we got login info in the URL
function checkForURLParams() {

    const urlParams = new URLSearchParams(window.location.search);
    let code = urlParams.get('code');
    let error = urlParams.get('error');
    let state = urlParams.get('state');

    if (code == null && state == null) { //} && state == getSessionState()) {

        return false; // nothing in the URL 
        
    } 

    if (state == null || getSessionState() == null || state != getSessionState()) {

        console.error(`Stored state: ${getSessionState()} \n Returned state: ${state}`);
        return false; // TODO: I gotta handle weirdness better ... 
        
    }

    if (error != null) {

        console.error(`Erro: ${error}`);
        return false; // TODO: I gotta handle weirdness better ...        
    }

    if (code == null) {

        console.error(`Code is null`);
         return false; // TODO: I gotta handle weirdness better ... 
      
    }

    storeSessionCode(code);
    return true;

}

function isLoggedIn() {

    return getSessionCode() != null;

}

async function presentLogin() {

    // clear out any code we may have stored
    storeSessionCode(null);

    // generate code_challenge & state 
    const codeVerifier  = generateRandomString(64);
    const hashed = await hashString(codeVerifier)
    const codeChallenge = base64encode(hashed);
    storeSessionState(codeChallenge);

    // stuff we need to know about
    const clientId = '004b4a3922474b05bd21e17a25df5de0';
    const redirectUri = 'https://davecarpeneto.github.io/spotifyApiTest';
    const scope = 'user-read-private user-read-email';
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

function liveItUp() {

    $("#main").html("IT WORKS");

}

function storeSessionCode(code) {

    if (code == null) {

        localStorage.removeItem("spotifyApiCode");

    } else {

        localStorage.setItem("spotifyApiCode", code);

    }

}

function storeSessionState(state) {

    if (state == null) {

        localStorage.removeItem("spotifyApiState");

    } else {

        localStorage.setItem("spotifyApiState", state);

    }

}

function getSessionCode() {

    return localStorage.getItem("spotifyApiCode");

}

function getSessionState() {

    return localStorage.getItem("spotifyApiState");

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

