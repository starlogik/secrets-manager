import { SecretsManager } from 'aws-sdk';
import { Logger } from 'writeln';
import fs from 'graceful-fs';
// import deasync from 'deasync';

interface ISection {
	[key: string]: string | ISection;
}

const logger = new Logger('secrets-manager');
const secretsManager = new SecretsManager({ region: 'eu-west-1' });
const jsonRegex = /{".+":.+}/;

// export function decryptSync<T extends {}>(filePath: string, pattern?: RegExp): T {
// 	let config: any;
//
// 	(async function () {
// 		config = await decrypt<T>(filePath, pattern);
// 	})();
//
// 	deasync.loopWhile(() => !config);
//
// 	return config as T;
// }

export async function decrypt<T>(filePathOrObject: string | {}, pattern = /^secret:(.+)$/): Promise<T> {
	let config: {};

	if (typeof(filePathOrObject) === 'string') {
		const json = await getFile(filePathOrObject);
		config = JSON.parse(json);
	}
	else {
		config = filePathOrObject;
	}

	await walkAndDecrypt(config, pattern);

	return config as T;
}

async function walkAndDecrypt(section: ISection, pattern: RegExp) {
	for (const key in section) {
		const val = section[key];

		if (typeof(val) === 'string') {
			const match = val.match(pattern);

			if (match !== null) {
				const decryptedVal = await decryptSecret(match[1]);

				if (decryptedVal)
					section[key] = decryptedVal;
			}
		}
		else {
			await walkAndDecrypt(val, pattern);
		}
	}
}

export async function decryptSecret(SecretId: string) {
	try {
		const { SecretString, SecretBinary } = await secretsManager.getSecretValue({ SecretId }).promise();

		if (SecretString) {
			if (jsonRegex.test(SecretString)) {
				logger.debug(`Decrypted secret JSON "${ SecretId }"`);
				return JSON.parse(SecretString);
			}
			else {
				logger.debug(`Decrypted secret string "${ SecretId }"`);
				return SecretString;
			}
		}
		else if (SecretBinary) {
			logger.debug(`Decrypted secret binary "${ SecretId }"`);

			const buffer = Buffer.from(SecretBinary.toString(), 'base64');
			return buffer.toString('ascii');
		}
		else {
			throw new Error(`Could not find value for "${ SecretId }"`);
		}
	}
	catch (err) {
		logger.error(err.message, err);
	}
}

function getFile(filePath: string) {
	return new Promise<string>(function (resolve, reject) {
		fs.readFile(filePath, 'ascii', (err, data) => {
			if (err) {
				reject(err);
			}
			else {
				resolve(data);
			}
		});
	});
}