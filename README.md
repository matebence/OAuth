# OAuth

- Authentication is 'who are you?'
- Authorization is 'what can you do?'

## What is OAuth?
OAuth is an open-standard authorization protocol or framework that provides applications the ability for “secure designated access.” For example, you can tell Facebook that it’s OK for ESPN.com to access your profile or post updates to your timeline without having to give ESPN your Facebook password.

	We never enter the password to the API, we enter the password to the authorization server

## What is OpenID?
OpenID is an extension of OAuth. Where OAuth does the authentication part and OpenID holds user information like id or username. 

OAuth issues
- Access tokens

Openid connect issues
 - Id tokens

	With other words OAuth is about accessing APIs and OpenID is about identifying the users

## Real world example 

What do OAuth 2.0 access tokens and hotel key cards have in common? It turns out quite a lot!

A hotel key card is essentially a physical counterpart to an OAuth access token. **At a hotel, you check in at the front desk, show your ID card**, and then you get a key card that you can use to get into your hotel room. In OAuth, the application sends the user over to the OAuth server where they authenticate (analogous to showing the ID card at the front desk), and the OAuth server will then issue an access token to the application. 

**A hotel key can be used by anyone who can get a hold of it**. If you give your hotel key to a friend, they can use your hotel key to get into your room. An OAuth access token works the same way, anyone who has the access token can use it to make API requests. That’s the reason they’re called “Bearer Tokens,” since the bearer of the token can use it at the API. 

**When the hotel gives you the key card, it’s your responsibility to keep it safe** and not lose it. When an access token is given to an application, the OAuth server expects the app to keep it safe. This is typically done by storing the access token in some sort of secure storage available to the application.

**A hotel key has no meaning to the application using it.** When you get a key card from the front desk clerk at the hotel, you don’t need to worry about what data the magnetic stripe contains, or whether the key is RFID or NFC. All you care about is whether the door will open when you swipe the card.

In addition to opening your hotel room, your hotel key **may also open the front door of the hotel after hours, the hotel pool room, or the gym**. Which doors the key can open will depend on the type of access you’re granted within the hotel. If you’re a Platinum Medallion Elite Pro status at your hotel, your key may also get you access to the executive lounge.

**If you lose your key card**, or if you get kicked out of the hotel for partying too hard, **the hotel can revoke**your key card immediately, and it will no longer open your hotel room door.

When you get a hotel key, it’s not like a regular physical key that will always open a certain door. **Hotel keys will stop working** at the end of your stay **because the expiration of the access** is encoded into the card.

## Roles in OAuth

User (**Resource owner**)
Device (**User agent**)
Application (**Client**)
API (**Resource server**)
Plus one role: **Authenrization server**

## Application Types

- Confidential - The server side application will be deployed with a client id and secret. These two informations are not visible to anyone.
- Public - These are mobile and SPA apps where we dont have any client id or sercret

## User Consent

At its core, user consent is the permission granted by users to a website or organization to proceed with their data collection. 

The format is the following: scope - description

In confidential client this step can be skipped (because its save).

## Front Channel vs Back Channel

The backchannel is used to obtain the token in the background between the app and the auth server without involving the user (Uses REST calls behind the scenes)

The frontchannel is used to obtain the token in the foreground between the browser and the app without involving the user (Uses the browser addressbar)

## Application Identity

Each applications has its own idenity called client id

## Type of flows

Client ID and secret can also be send as Basic Auth clientId:secret

[OAuth2 playground](https://www.oauth.com/playground/)
[Google playground](https://developers.google.com/oauthplayground/)

- ** 1. Authorization Code Flow **

Authorization Code Flow exchanges an authorization code for a token. For this exchange to take place, you have to also pass along your app’s client id and secret. The secret must be securely stored on the client side.

Use Cases: Server side web applications where the source code is not exposed publicly.

How this OAuth flow works:
- The user clicks on a login link in the web application.
- The user is redirected to an OAuth authorization server, after which an OAuth login prompt is issued.
- The user provides credentials according to the enabled login options.
- Typically, the user is shown a list of permissions that will be granted to the web application by logging in and granting consent. (can be skipped)
- The user is redirected to the application, with the authorization server providing a one-time authorization code.
- The app receives the user’s authorization code and forwards it along with the Client ID and Client Secret, to the OAuth authorization server.
- The authorization server generates an ID Token, Access Token, and an optional Refresh Token, before providing them them to the app.
- The web application can then use the Access Token to gain access to the target API with the user’s credentials.

** cURL example **

```bash
curl https://authorization-server.com/auth?
	response_type=code&
	client_id=CLIENT_ID&
	redirect_URI=REDIRECT_URI&
	scope=phote&
	state=XXXXXXX
```
	
```bash
curl https://example-app.com/redirect?
    code=AUTH_CODE_HERE&
    state=XXXXXXX		
```

```bash
curl https://authorization-server.com/token
    grant_type=authorization_code&
    code=AUTH_CODE_HERE&
    redirect_URI=REDIRECT_URI&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET
```

```bash
curl https://authorization-server.com/token
	grant_type=refresh_token&
	refresh_token=REFRESH_TOKEN&
	client_id=CLIENT_ID&
	client_secret=CLIENT_SECRET
```

- ** 2. Client Credentials Flow **

The Client Credentials Flow allows applications to pass their Client Secret and Client ID to an authorization server, which authenticates the user, and returns a token. This happens without any user intervention.

Relevant for: M2M apps (daemons, back-end services, and CLIs). In these types of apps, the system authenticates and grants permission behind the scenes without involving the user, because the “user” is often a machine or service role. It doesn’t make sense to show a login prompt or use social logins.

How this OAuth flow works:

- The application authenticates with the OAuth authorization server, passing the Client Secret and Client ID.
- The authorization server checks the Client Secret and Client ID and returns an Access Token to the application.
- The Access Token allows the application to access the target API with the required user account.

** cURL example **

```bash
https://api.authorization-server.com/token
    grant_type=client_credentials&
    scope=contacts&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET
```

- ** 3. Resource Owner Password Flow **

The Resource Owner Password Flow asks users to submit their credentials via a form. Credentials are transferred to the backend and may be retained for future use, before an Access Token is granted. It’s essential that the app is completely trusted. Therefore, this flow is generally not recommended.

Use Cases: Highly-trusted applications, where other flows based on redirects cannot be used.

How this OAuth flow works:
- The user clicks a login link in the application and enters credentials into a form managed by the app.
- The application stores the credentials, and passes them to the OAuth authorization server.
- The authorization server validates credentials and returns the Access Token (and an optional Refresh Token).
- The app can now access the target API with the user’s credentials.

```bash
curl https://authorization-server.com/auth?
    grant_type=password&
    scope=contacts&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET
  --data grant_type=password \
  --data username=user@example.com \
  --data password=pwd \
```

- ** 4. Implicit Flow **

This flow uses OIDC to implement a web sign-in that functions like WS-Federation and SAML. The web app requests and receives tokens via the front channel, without requiring extra backend calls or secrets. With this process, you don’t have to use, maintain, obtain or safeguard secrets in your app. 

Use Cases: Apps that don’t want to maintain secrets locally.

** cURL example **

```bash
curl https://authorization-server.com/auth?
	response_type=token&
	client_id=CLIENT_ID&
	redirect_uri=REDIRECT_URI&
	scope=photo&
	state=XXXXXXXXX
```

The user was redirected back to the client, and you'll notice there is now a fragment component in the URL that contains the access token as well as some other information:

    #access_token=ADcSqzxwt5hquOwRhSo_o4rVQKlEJct66Cs1yIBkl2Z87nQ-Rmy0_Gvis8yTkpUTVwK5r_xN&token_type=Bearer&expires_in=86400&scope=photos&state=XSlF9uFLyqF3HDdG	

- ** 6. Device Authorization Flow **

This flow makes it possible to authenticate users without asking for their credentials. This provides a better user experience for mobile devices, where it may be more difficult to type credentials. Applications on these devices can transfer their Client ID to the Device Authorization Flow to start the authorization process and obtain a token.

Use Cases: Apps running on input-constrained devices that are online, enabling seamless authentication via credentials stored on the device.

** cURL example **

```bash
curl https://authorization-server.com/device
    client_id=CLIENT_ID&
    scope=youtube
```

The server respons with a new device code, user code as well as with a URL that the user should visit to enter the code. Mean while the device waits for the user to enter the code and authorize the application, the device pools the token endpoint.

```json
{
    "device_code": "WKHL4897FSWe789",
    "user_code": "BWD-789",
    "verification_uri": "https://exampple.com",
    "expires_in": 1800,
    "interval": 5
}
```

```bash
curlhttps://authorization-server.com/token
    grant_type=urn:ietf:params:ouath:grant-type:device_code&
    client_id=CLIENT_ID&
    device_code=WKHL4897FSWe789
    --data user_code=BWD-789
```

- ** 7. Authorization Code Flow with PKCE ** 

This flow uses a proof key for code exchange (PKCE). A secret known as a Code Verifier is provided by the calling application, which may be verified by the authorization server using a Proof Key. 

Use Cases: Apps that need to serve unknown public clients who may introduce additional security issues that are not addressed by the Auth Code Flow. 

** cURL example **

```bash
curl https://authorization-server.com/auth?
	response_type=code&
	client_id=CLIENT_ID&
	redirect_URI=REDIRECT_URI&
	scope=phote&
	state=XXXXXXX&
	code_challange=XXXXXXXX&
	code_challange_method=S256
```
	
```bash
curl https://example-app.com/redirect?
    code=AUTH_CODE_HERE&
    state=XXXXXXX		
```

```bash
curl https://authorization-server.com/token
    grant_type=authorization_code&
    code=AUTH_CODE_HERE&
    redirect_URI=REDIRECT_URI&
    code_verifier=VERIFIER_STRING&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET
```

```bash
curl https://authorization-server.com/token
	grant_type=refresh_token&
	refresh_token=REFRESH_TOKEN&
	client_id=CLIENT_ID&
	client_secret=CLIENT_SECRET
```

- ** 8. Hybrid** 

Due to the inherent risks of performing an OAuth flow in a pure JavaScript environment, as well as the risks of storing tokens in a JavaScript app, it is also advisable to consider an alternative architecture where the OAuth flow is handled outside of the JavaScript code by a dynamic backend component. This is a relatively common architectural pattern where an application is served from a dynamic backend such as a .NET or Java app, but it uses a single-page app framework like React or Angular for its UI. If your app falls under this architectural pattern, then the best option is to move all of the OAuth flow to the server component, and keep the access tokens and refresh tokens out of the browser entirely. Note that in this case since your app has a dynamic backend, it is also considered a confidential client and can use a client secret to further protect the OAuth exchanges.

## Retrieving ID tokens

The main goal of id tokens are transferring information to the APIs

** cURL example **

```bash
curl https://authorization-server.com/auth?
	response_type=code&
	client_id=CLIENT_ID&
	redirect_URI=REDIRECT_URI&
    scope=phote+openid&
	state=XXXXXXX&
	code_challange=XXXXXXXX&
	code_challange_method=S256
```
	
```bash
curl https://example-app.com/redirect?
    code=AUTH_CODE_HERE&
    state=XXXXXXX		
```

```bash
curl https://authorization-server.com/token
    grant_type=authorization_code&
    code=AUTH_CODE_HERE&
    redirect_URI=REDIRECT_URI&
    code_verifier=VERIFIER_STRING&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET
```

## Protecting Tokens

- Secure storage on smart phones
- WebCrypto API - asymmetric keys
- Service workers - JS
- HTTP only cookies -  The HTTP-Only cookie nature is that it will be only accessible by the server application. Client apps like javascript-based apps can't access the HTTP-Only cookie.
- Store in memory

## Validating tokens

A token consits of tree parts:

- header
- payload
- signature

Check token contents:

- iss - is it our authorization server ??
- aud - is it our client id ??
- iat - does it match our time range ??
- axp - does it match our time range ?? 

Using token introspect endpoint:

```bash
curl https://authorization-server.com/introspect
    token=THE_TOKEN
```

```json
{
    "active": true,
}					
```

Using public keys:

How to get the public key?
https://authorization-server.com/.well-known/oauth-authorization-server
jwks_uri - we copy the uri from the attribute and visit the website, here we will see all the keys
To find our key we use the kid attribute 

Validate signuture:

```json
{
    "kid": "g465wqe789fq789weqweqw",
    "alg": "RS256"
}
```

Which should we use??
API gateway should do local validations for all
Token interpestion via network only for sensetive APIs like payment etc ....

Token lifetimes (can be improved via refresh tokens):

- Short life times less leaked access tokens
- Sensitive API short life time
- NonSensitive API long life time

Possible reasons for token invalidations:

- when a client revokes access to a app
- admin removes a user
- client logs out
- password change

## OAuth scopes

It limits what a access token can do

Styles:
- 1: Simple strings
    - repo
    - repo:status
    - read
    - write
    - public_repo
- 2: Java namespaces
    - com.app.resource
    - com.app.resource.read
    - com.app.resource.write
- 3: URL
    - https://api.company.com/resources
    - https://api.company.com

User Mapping with scopes:

## Endpoints

## Summary