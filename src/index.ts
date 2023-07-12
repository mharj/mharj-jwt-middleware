import * as EventEmitter from 'events';
import {isGroupOptions, JwtVerifyGroupsOptions} from './interfaces/group';
import {isRoleOptions, JwtVerifyRoleOptions} from './interfaces/role';
import {JwtResponse, jwtVerify} from 'mharj-jwt-util';
import {NextFunction, Request, RequestHandler, Response} from 'express';
import {ErrorCallbackType} from './errors';
import {ILoggerLike} from '@avanio/logger-like';
import {JwtGroupError} from './errors/JwtGroupError';
import {JwtHeaderError} from 'mharj-jwt-util/dist/JwtHeaderError';
import {JwtRoleError} from './errors/JwtRoleError';
import TypedEmitter from 'typed-emitter';
import {VerifyOptions} from 'jsonwebtoken';
export {useCache, FileCertCache} from 'mharj-jwt-util';

export type AadTokenBodyClaims = {
	roles?: string[];
	groups?: string[];
};

type AadJwtResponse = JwtResponse<AadTokenBodyClaims>;

type ValidatedCallback = (payload: AadJwtResponse, req: Request, res: Response) => Promise<void>;

type JwtEvents = {
	validated: (payload: AadJwtResponse, req: Request | undefined, res: Response | undefined) => void;
};

type JwtVerifyOptions = JwtVerifyRoleOptions | JwtVerifyGroupsOptions;

type JwtMiddlewareOptions = VerifyOptions | Promise<VerifyOptions> | (() => VerifyOptions | Promise<VerifyOptions>);

/**
 * @example
 * const jwt = new JwtMiddleware({
 *   issuer: `https://sts.windows.net/${process.env.AZURE_TENANT_ID}/`,
 *   audience: `${process.env.AZURE_API_AUDIENCE}`,
 * });
 */
export class JwtMiddleware extends (EventEmitter as new () => TypedEmitter<JwtEvents>) {
	private options: JwtMiddlewareOptions;
	private roleErrorCallback: ErrorCallbackType | undefined;
	private groupErrorCallback: ErrorCallbackType | undefined;
	private validatedCallback: ValidatedCallback | undefined;
	private logger: ILoggerLike | undefined;
	public constructor(options: JwtMiddlewareOptions = {}, logger?: ILoggerLike) {
		super();
		this.options = options;
		this.logger = logger;
	}

	public onRoleError(callback: ErrorCallbackType) {
		this.roleErrorCallback = callback;
	}

	public onGroupError(callback: ErrorCallbackType) {
		this.groupErrorCallback = callback;
	}

	/**
	 * onOnValidated callback
	 * @example
	 * jwt.onValidated(async (payload, req, res) => {
	 *   await isValidTenantId(payload.body.tid);
	 *   res.locals.tokenBody = payload.body;
	 * });
	 */
	public onValidated(callback: ValidatedCallback) {
		this.validatedCallback = callback;
	}

	/**
	 * Jwt Verify and if needed, role/group claim validation
	 * @param token
	 * @param verifyOptions
	 * @returns token body
	 * @throws JwtRoleError | JwtGroupError | JwtHeaderError | JsonWebTokenError | NotBeforeError | TokenExpiredError
	 * @example
	 * try {
	 *   const {isCached, body} = await jwt.verifyToken(accessToken, {roles: ['Something.Read', 'Something.Write']});
	 * } catch (err) {
	 *   // handle validation failed
	 * }
	 */
	public async verifyToken<T = AadTokenBodyClaims>(
		token: string,
		verifyOptions?: JwtVerifyOptions,
		req?: Request,
		res?: Response,
	): Promise<JwtResponse<T & object>> {
		const options = await this.getOptions();
		const payload = await jwtVerify<T & object>(token, options);
		if (isRoleOptions(verifyOptions) && !this.haveRole(verifyOptions, payload)) {
			this.logger?.info(payload.body, 'not match with roles', verifyOptions.roles);
			throw new JwtRoleError('no matching role');
		}
		if (isGroupOptions(verifyOptions) && !this.haveGroup(verifyOptions, payload)) {
			this.logger?.info(payload.body, 'not match with groups', verifyOptions.groups);
			throw new JwtGroupError('no matching group');
		}
		this.emit('validated', payload, req, res);
		return payload;
	}

	/**
	 * Express middleware to verify JWT and possible role or group claims from token
	 * @param verifyOptions
	 * @param {string[]} verifyOptions.roles valid roles from JWT role claim (i.e. Application Roles)
	 * @param {string[]} verifyOptions.groups valid groups from JWT groups claim (expose group claims, App registrations => Token Configuration => Add groups claim)
	 * @example
	 * app.get('/', jwt.verify({groups: ['SomeRole.Read', 'SomeRole.Write']}), (req, res, next) => {
	 * });
	 */
	public verify(verifyOptions?: JwtVerifyOptions): RequestHandler {
		return async (req, res, next) => {
			try {
				if (!req.headers.authorization) {
					throw new JwtHeaderError('no authorization header');
				}
				const options = await this.getOptions();
				const payload = await jwtVerify<AadTokenBodyClaims>(req.headers.authorization, options);
				if (isRoleOptions(verifyOptions)) {
					if (this.haveRole(verifyOptions, payload)) {
						await this.handleValidLogin(payload, req, res);
						return next();
					}
					this.logger?.info(payload.body, 'not match with roles', verifyOptions.roles);
					return this.handleRoleError(payload, req, res, next);
				}
				if (isGroupOptions(verifyOptions)) {
					if (this.haveGroup(verifyOptions, payload)) {
						await this.handleValidLogin(payload, req, res);
						return next();
					}
					this.logger?.info(payload.body, 'not match with groups', verifyOptions.groups);
					return this.handleGroupError(payload, req, res, next);
				}
				await this.handleValidLogin(payload, req, res);
				next();
			} catch (err) {
				next(err);
			}
		};
	}

	private haveRole(verifyOptions: JwtVerifyRoleOptions, payload: JwtResponse<AadTokenBodyClaims>): boolean {
		const payloadRoles = payload.body?.roles || [];
		return verifyOptions.roles.some((role) => payloadRoles.includes(role));
	}

	private haveGroup(verifyOptions: JwtVerifyGroupsOptions, payload: JwtResponse<AadTokenBodyClaims>): boolean {
		const payloadGroups = payload.body?.groups || [];
		return verifyOptions.groups.some((group) => payloadGroups.includes(group));
	}

	private handleRoleError(payload: AadJwtResponse, req: Request, res: Response, next: NextFunction) {
		// if have custom callback
		if (this.roleErrorCallback) {
			this.roleErrorCallback(payload, req, res, next);
		} else {
			next(new JwtRoleError('no matching role'));
		}
	}

	private handleGroupError(payload: AadJwtResponse, req: Request, res: Response, next: NextFunction) {
		// if have custom callback
		if (this.groupErrorCallback) {
			this.groupErrorCallback(payload, req, res, next);
		} else {
			next(new JwtGroupError('no matching group'));
		}
	}

	private async handleValidLogin(payload: AadJwtResponse, req: Request, res: Response): Promise<void> {
		if (this.validatedCallback) {
			this.validatedCallback(payload, req, res);
		}
		this.emit('validated', payload, req, res);
	}

	private getOptions(): VerifyOptions | Promise<VerifyOptions> {
		return typeof this.options === 'function' ? this.options() : this.options;
	}
}
