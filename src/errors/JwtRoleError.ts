export class JwtRoleError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'JwtRoleError';
		Error.captureStackTrace(this, this.constructor);
	}
}