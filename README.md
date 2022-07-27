# Express JWT Middleware and JWT verify method with token role/group claim validation

## install

```
npm i mharj-jwt-middleware
```

## Examples

```typescript
// setup strict issuer and audience validation for JWT verify
const jwt = new JwtMiddleware(
	{
		issuer: `https://sts.windows.net/${process.env.AZURE_TENANT_ID}/`,
		audience: `${process.env.AZURE_API_AUDIENCE}`,
	},
	optionalLogger,
);

// or have validation options as async function
async function buildOptions(): Promise<VerifyOptions> {
	return {
		issuer: `https://sts.windows.net/${await getIssuer()}/`,
		audience: await getAudience(),
	}
}
const jwt = new JwtMiddleware(buildOptions, optionalLogger);

// (optional) if need cert cache support for restarts
useCache(new FileCertCache());
```

Use as validation function to validate token and match any of roles (or groups)

```typescript
try {
	const {isCached, body} = await jwt.verifyToken(accessToken, {roles: ['Something.Read', 'Something.Write']});
} catch (err) {
	// handle validation failed
}
```

Use as express middleware

```typescript
// plain JWT verify without claim checking
app.get('/', jwt.verify(), (req, res, next) => {});

// JWT with role claim validation (i.e. Azure AD Application roles)
app.get('/', jwt.verify({roles: ['Something.Read', 'Something.Write']}), (req, res, next) => {});

// JWT with group claim validation (i.e. Group ID), set on AzureAD add Group claim types to token
app.get('/', jwt.verify({groups: ['4d6fd610-d418-4cc6-8dc5-9d693d39c164', '4d0b29a7-fb1e-4aad-89b3-636a55c07d7c']}), (req, res, next) => {});
```

This uses expressjs error middleware to pass errors (claim errors to be instanceof JwtGroupError or JwtRoleError), but if need custom handling instead

```typescript
jwt.onRoleError(({isCached, body}, req, res, next) => {
	res.status(401).end();
});

jwt.onGroupError(({isCached, body}, req, res, next) => {
	res.status(401).end();
});
```

Validation callback and event emitter for middleware

```typescript
// (optional) callback as example extend req to contain tokenBody
jwt.onValidated(({isCached, body}, req: JwtRequest, res) => {
	req.tokeBody = body;
	return Promise.resolve(); // or async
});

// (optional) validated events with JWT payload, request and response, as example to log new tokens
jwt.on('validated', ({isCached, body}, req, res) => {
	!isCached && logger.info(`${body.upn} login from ${req.ip} with roles ${body.roles}`);
});
```
