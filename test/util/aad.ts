import {useIdentityPlugin, AzurePowerShellCredential, AzureCliCredential, ChainedTokenCredential, VisualStudioCodeCredential} from '@azure/identity';
import {vsCodePlugin} from '@azure/identity-vscode';
useIdentityPlugin(vsCodePlugin);
/**
 * get Azure user credentials from VSCode, Powershell or Azure CLI
 * "DefaultAzureCredential" is doing same but also gets confused with current ENV variables we have.
 * @see https://www.npmjs.com/package/@azure/identity#defaultazurecredential
 *
 * Order: [VS Code] => [Powershell] => [Azure CLI]
 */
export function getDeveloperCredentials(): ChainedTokenCredential {
	return new ChainedTokenCredential(new VisualStudioCodeCredential(), new AzurePowerShellCredential(), new AzureCliCredential());
}
