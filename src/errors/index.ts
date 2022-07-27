import {Request, Response, NextFunction} from 'express';
import {JwtResponse} from 'mharj-jwt-util';
export {JwtGroupError} from './JwtGroupError';
export {JwtRoleError} from './JwtRoleError';

export type ErrorCallbackType = (
	payload: JwtResponse<{
		roles?: string[];
		groups?: string[];
	}>,
	req: Request,
	res: Response,
	next: NextFunction,
) => void;
