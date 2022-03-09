import * as dotenv from 'dotenv';
dotenv.config();
process.env.NODE_ENV = 'testing';
import * as sinon from 'sinon';
import {expect} from 'chai';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import 'cross-fetch/polyfill';
import 'mocha';
import {Request, Response, NextFunction} from 'express';
import {JwtMiddleware, useCache, FileCertCache} from '../src';
import {startExpress, stopExpress} from './util/express';
import {JwtGroupError} from '../src/errors/JwtGroupError';
import {JwtRoleError} from '../src/errors/JwtRoleError';
import {ErrorCallbackType} from '../src/errors';

const port = '12345';

// tslint:disable: no-unused-expression
chai.use(chaiAsPromised);

let jwt: JwtMiddleware;
let lastError: Error | undefined;

describe('aadMiddleware', () => {
	before(async function () {
		this.timeout(30000);
		useCache(new FileCertCache({fileName: '.certCache.json', pretty: true}));
		jwt = new JwtMiddleware({issuer: `https://sts.windows.net/${process.env.AZURE_TENANT_ID}/`, audience: `${process.env.AZURE_API_AUDIENCE}`});
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
	});
	beforeEach(() => {
		lastError = undefined;
	});
	describe('token validation', () => {
		it('should handle different role and group validations', async function () {
			if (!process.env.VALID_ROLE) {
				throw new Error('no VALID_ROLE set');
			}
			if (!process.env.VALID_GROUP) {
				throw new Error('no VALID_GROUP set');
			}
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			await expect(jwt.verifyToken(process.env.ACCESS_TOKEN)).to.be.eventually.an('object');
			await expect(jwt.verifyToken(process.env.ACCESS_TOKEN, {roles: [process.env.VALID_ROLE]})).to.be.eventually.an('object');
			await expect(jwt.verifyToken(process.env.ACCESS_TOKEN, {groups: [process.env.VALID_GROUP]})).to.be.eventually.an('object');
			await expect(jwt.verifyToken(process.env.ACCESS_TOKEN, {roles: ['THIS DOES NOT EXISTS']})).to.be.eventually.rejectedWith(
				JwtRoleError,
				'no matching role',
			);
			await expect(jwt.verifyToken(process.env.ACCESS_TOKEN, {groups: ['THIS DOES NOT EXISTS']})).to.be.eventually.rejectedWith(
				JwtGroupError,
				'no matching group',
			);
		});
	});
	describe('basic errors', () => {
		it('should fail if no auth header', async function () {
			this.timeout(30000);
			const res = await fetch(`http://localhost:${port}/unit1`);
			expect(res.status).to.be.eq(500);
			expect(lastError?.message).to.be.eq('no authorization header');
		});
		it('should fail if wrong type auth header', async function () {
			this.timeout(30000);
			const headers = new Headers();
			headers.set('Authorization', `Basic asd:qwe`);
			const res = await fetch(`http://localhost:${port}/unit1`, {headers});
			expect(res.status).to.be.eq(500);
			expect(lastError?.message).to.be.eq('token header: wrong authentication header type');
		});
	});
	describe('jwtVerifyPromise', () => {
		it('should have valid role in token', async function () {
			this.timeout(30000);
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit1`, {headers});
			expect(res.status).to.be.eq(200);
		});
		it('should have valid group in token', async function () {
			this.timeout(30000);
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit2`, {headers});
			expect(res.status).to.be.eq(200);
		});
		it('should not have valid role in token', async function () {
			this.timeout(30000);
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit3`, {headers});
			expect(res.status).to.be.eq(401);
		});
		it('should not have valid group in token', async function () {
			this.timeout(30000);
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit4`, {headers});
			expect(res.status).to.be.eq(401);
		});
		it('should have valid token without role or group check', async function () {
			this.timeout(30000);
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit5`, {headers});
			expect(res.status).to.be.eq(200);
		});
		it('should trigger event then login', async function () {
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const emitSpy = sinon.spy();
			jwt.on('validated', emitSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit2`, {headers});
			expect(res.status).to.be.eq(200);
			expect(emitSpy.calledOnce).to.be.eq(true);
			jwt.removeAllListeners();
		});
		it('should trigger onValidated then login', async function () {
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const emitSpy = sinon.spy();
			jwt.onValidated(emitSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit2`, {headers});
			expect(res.status).to.be.eq(200);
			expect(emitSpy.calledOnce).to.be.eq(true);
			jwt.removeAllListeners();
		});
	});
	describe('onRoleError', () => {
		it('should not have valid role in token', async function () {
			this.timeout(30000);
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const emitSpy = sinon.spy<ErrorCallbackType>((payload, req, res) => res.status(401).end());
			jwt.onRoleError(emitSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit3`, {headers});
			expect(res.status).to.be.eq(401);
			expect(emitSpy.calledOnce).to.be.eq(true);
		});
	});
	describe('onGroupError', () => {
		it('should not have valid role in token', async function () {
			this.timeout(30000);
			if (!process.env.ACCESS_TOKEN) {
				throw new Error('no token found!');
			}
			const emitSpy = sinon.spy<ErrorCallbackType>((payload, req, res) => res.status(401).end());
			jwt.onGroupError(emitSpy);
			const headers = new Headers();
			headers.set('Authorization', `Bearer ${process.env.ACCESS_TOKEN}`);
			const res = await fetch(`http://localhost:${port}/unit4`, {headers});
			expect(res.status).to.be.eq(401);
			expect(emitSpy.calledOnce).to.be.eq(true);
		});
	});
	after(async function () {
		this.timeout(30000);
		await stopExpress();
	});
});
