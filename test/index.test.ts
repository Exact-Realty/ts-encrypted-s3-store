/* Copyright © 2023 Exact Realty Limited. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

import { AwsClient } from 'aws4fetch';
import assert from 'node:assert/strict';
import { decryptFile, deleteFile, encryptFile } from '../src/index.js';

const BASE_URI = process.env['BASE_URI'] ?? '';
const ACCESS_KEY_ID = process.env['ACCESS_KEY_ID'] ?? '';
const SECRET_ACCESS_KEY = process.env['SECRET_ACCESS_KEY'] ?? '';

describe('S3 Encrypted Store', () => {
	it('can encrypt and decrypt files', async function () {
		this.timeout(30e3);

		const awsClient = new AwsClient({
			accessKeyId: ACCESS_KEY_ID,
			secretAccessKey: SECRET_ACCESS_KEY,
		});

		const wrapKey = await globalThis.crypto.subtle.generateKey(
			{
				name: 'AES-KW',
				length: 256,
			},
			true,
			['wrapKey', 'unwrapKey'],
		);

		const r = await encryptFile(
			awsClient,
			BASE_URI,
			'test',
			'1234',
			wrapKey,
		);

		const s = await decryptFile(awsClient, BASE_URI, 'test', wrapKey, ...r);

		assert.deepEqual(
			Array.from(new Uint8Array(s)),
			'1234'.split('').map((c) => c.charCodeAt(0)),
		);

		const r2 = await encryptFile(
			awsClient,
			BASE_URI,
			'test',
			'5678',
			wrapKey,
		);

		const s2_wrongkey = decryptFile(
			awsClient,
			BASE_URI,
			'test',
			wrapKey,
			...r,
		);

		await assert.rejects(s2_wrongkey);

		const s2 = await decryptFile(
			awsClient,
			BASE_URI,
			'test',
			wrapKey,
			...r2,
		);

		assert.deepEqual(
			Array.from(new Uint8Array(s2)),
			'5678'.split('').map((c) => c.charCodeAt(0)),
		);

		const dr = await deleteFile(awsClient, BASE_URI, 'test');

		assert.ok(dr.ok);
	});
});
