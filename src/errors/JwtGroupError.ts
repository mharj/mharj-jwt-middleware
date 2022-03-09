export class JwtGroupError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'JwtGroupError';
		Error.captureStackTrace(this, this.constructor);
	}
}