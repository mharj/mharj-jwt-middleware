export interface JwtVerifyGroupsOptions {
	groups: string[];
}
export function isGroupOptions(options: unknown): options is JwtVerifyGroupsOptions {
	return options !== null && typeof options === 'object' && 'groups' in options;
}
