import {describe, it, beforeAll, beforeEach, expect, afterAll, vi} from 'vitest';
import {z} from 'zod';
import * as dotenv from 'dotenv';
import {Request, Response, NextFunction} from 'express';
import {useCache, FileCertCache, type CertRecordsSchema} from '@luolapeikko/oidc-jwt-verify';
import {startExpress, stopExpress} from './util/express';
import {JwtGroupError} from '../src/errors/JwtGroupError';
import {JwtRoleError} from '../src/errors/JwtRoleError';
import {ErrorCallbackType} from '../src/errors/ErrorCallbackType';
import {getDeveloperCredentials} from './util/aad';
import {AccessToken} from '@azure/identity';
import {JwtMiddleware} from '../src';

dotenv.config();

const port = '12345';

const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies CertRecordsSchema;

let tokenResponse: AccessToken;

let jwt: JwtMiddleware;
let lastError: Error | undefined;

const emitValidatedSpy = vi.fn();
const emitRoleErrorSpy = vi.fn<ErrorCallbackType>((payload, req, res) => res.status(401).end());
const emitGroupErrorSpy = vi.fn<ErrorCallbackType>((payload, req, res) => res.status(401).end());

describe('aadMiddleware', () => {
	beforeAll(async function () {
		useCache(new FileCertCache({fileName: '.certCache.json', schema: certCacheSchema, pretty: true}));
		jwt = new JwtMiddleware(() =>
			Promise.resolve({issuer: `https://sts.windows.net/${process.env.AZURE_TENANT_ID}/`, audience: `${process.env.AZURE_API_AUDIENCE}`}),
		);
		const app = await startExpress(port);
		if (!process.env.VALID_ROLE) {
			throw new Error('no VALID_ROLE set');
		}
		if (!process.env.VALID_GROUP) {
			throw new Error('no VALID_GROUP set');
		}
		app.get('/unit1', jwt.verify({roles: [process.env.VALID_ROLE]}), (req, res, next) => {
			res.end();
		});
		app.get('/unit2', jwt.verify({groups: [process.env.VALID_GROUP]}), (req, res, next) => {
			res.end();
		});
		app.get('/unit3', jwt.verify({roles: ['THIS DOES NOT EXISTS']}), (req, res, next) => {
			res.end();
		});
		app.get('/unit4', jwt.verify({groups: ['THIS DOES NOT EXISTS']}), (req, res, next) => {
			res.end();
		});
		app.get('/unit5', jwt.verify(), (req, res, next) => {
			res.end();
		});
		app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
			lastError = err;
			res.statusCode = 500;
			if (err instanceof JwtGroupError) {
				res.statusCode = 401;
			}
			if (err instanceof JwtRoleError) {
				res.statusCode = 401;
			}
			res.end();
		});
		const response = getDeveloperCredentials();
		tokenResponse = await response.getToken([`${process.env.AZURE_API_AUDIENCE}/.default`]);
	}, 60000);
	beforeEach(() => {
		lastError = undefined;
		emitValidatedSpy.mockClear();
		emitRoleErrorSpy.mockClear();
		emitGroupErrorSpy.mockClear();
	});
	describe('token validation', () => {
		it('should handle different role and group validations', async function () {
			if (!process.env.VALID_ROLE) {
				throw new Error('no VALID_ROLE set');
			}
			if (!process.env.VALID_GROUP) {
				throw new Error('no VALID_GROUP set');
			}
			await jwt.verifyToken(tokenResponse.token);
			console.log('tokenResponse', tokenResponse);
			await expect(jwt.verifyToken(tokenResponse.token)).resolves.an('object');
			await expect(jwt.verifyToken(tokenResponse.token, {roles: [process.env.VALID_ROLE]})).resolves.an('object');
			await expect(jwt.verifyToken(tokenResponse.token, {groups: [process.env.VALID_GROUP]})).resolves.an('object');
			await expect(jwt.verifyToken(tokenResponse.token, {roles: ['THIS DOES NOT EXISTS']})).rejects.toThrow(JwtRoleError);
			await expect(jwt.verifyToken(tokenResponse.token, {groups: ['THIS DOES NOT EXISTS']})).rejects.toThrow(JwtGroupError);
		});
	});
	describe('basic errors', () => {
		it('should fail if no auth header', async function () {
			const res = await fetch(`http://localhost:${port}/unit1`);
			expect(res.status).to.be.eq(500);
			expect(lastError?.message).to.be.eq('no authorization header');
		});
		it('should fail if wrong type auth header', async function () {
			const headers = new Headers();
			headers.set('Authorization', `Basic asd:qwe`);
			const res = await fetch(`http://localhost:${port}/unit1`, {headers});
			expect(res.status).to.be.eq(500);
			expect(lastError?.message).to.be.eq('token header: Not JWT token string format');
		});
	});
	describe('jwtVerifyPromise', () => {
		it('should have valid role in token', async function () {
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit1`, {headers});
			expect(res.status).to.be.eq(200);
		});
		it('should have valid group in token', async function () {
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit2`, {headers});
			expect(res.status).to.be.eq(200);
		});
		it('should not have valid role in token', async function () {
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit3`, {headers});
			expect(res.status).to.be.eq(401);
		});
		it('should not have valid group in token', async function () {
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit4`, {headers});
			expect(res.status).to.be.eq(401);
		});
		it('should have valid token without role or group check', async function () {
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit5`, {headers});
			expect(res.status).to.be.eq(200);
		});
		it('should trigger event then login', async function () {
			jwt.on('validated', emitValidatedSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit2`, {headers});
			expect(res.status).to.be.eq(200);
			expect(emitValidatedSpy).toHaveBeenCalledOnce();
			jwt.removeAllListeners();
		});
		it('should trigger onValidated then login', async function () {
			jwt.onValidated(emitValidatedSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit2`, {headers});
			expect(res.status).to.be.eq(200);
			expect(emitValidatedSpy).toHaveBeenCalledOnce();
			jwt.removeAllListeners();
		});
	});
	describe('onRoleError', () => {
		it('should not have valid role in token', async function () {
			jwt.onRoleError(emitRoleErrorSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit3`, {headers});
			expect(res.status).to.be.eq(401);
			expect(emitRoleErrorSpy).toHaveBeenCalledOnce();
		});
	});
	describe('onGroupError', () => {
		it('should not have valid role in token', async function () {
			jwt.onGroupError(emitGroupErrorSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${tokenResponse.token}`);
			const res = await fetch(`http://localhost:${port}/unit4`, {headers});
			expect(res.status).to.be.eq(401);
			expect(emitGroupErrorSpy).toHaveBeenCalledOnce();
		});
	});
	afterAll(async function () {
		await stopExpress();
	});
});
