import type {NextFunction, Request, Response} from 'express';
import type {JwtResponse} from '@luolapeikko/oidc-jwt-verify';

export type ErrorCallbackType = (
	payload: JwtResponse<{
		roles?: string[];
		groups?: string[];
	}>,
	req: Request,
	res: Response,
	next: NextFunction,
) => void;