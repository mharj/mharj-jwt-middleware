import {Server} from 'http';
import * as express from 'express';

let server: undefined | Server;

export const startExpress = async (port: string | number): Promise<express.Express> => {
	const app = express();
	return new Promise((resolve, reject) => {
		if (!app) {
			reject(new Error('no express instance found'));
		} else {
			server = app.listen(port, () => {
				resolve(app);
			});
		}
	});
};

export const stopExpress = (): Promise<void> => {
	return new Promise((resolve, reject) => {
		if (server) {
			server.close((err) => {
				if (err) {
					reject(err);
				} else {
					resolve();
				}
			});
		} else {
			resolve();
		}
	});
};
