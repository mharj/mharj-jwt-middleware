export interface JwtVerifyRoleOptions {
	roles: string[];
}

export function isRoleOptions(options: unknown): options is JwtVerifyRoleOptions {
	return options !== null && typeof options === 'object' && 'roles' in options;
}
