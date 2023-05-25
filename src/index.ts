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
import { autobb, btoau } from './lib/base64url.js';

const encryptFile = async (
	awsClient: AwsClient,
	baseUri: string,
	name: string,
	data: string | BufferSource,
	wrappingKey: CryptoKey,
	requestInit?: RequestInit,
): Promise<[string, string]> => {
	const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

	const encryptionKey = await globalThis.crypto.subtle.generateKey(
		{
			['name']: 'AES-GCM',
			['length']: 256,
		},
		true,
		['encrypt'],
	);

	const wrappedEncryptionKey = await globalThis.crypto.subtle.wrapKey(
		'raw',
		encryptionKey,
		wrappingKey,
		{ ['name']: 'AES-KW' },
	);

	const dataBuffer =
		typeof data === 'string' || data instanceof String
			? new Uint8Array(data.split('').map((c) => c.charCodeAt(0)))
			: data;

	const encryptedData = await globalThis.crypto.subtle.encrypt(
		{ ['name']: 'AES-GCM', ['iv']: iv },
		encryptionKey,
		dataBuffer,
	);

	const response = await awsClient.fetch(
		`${baseUri}/${encodeURIComponent(name)}`,
		{
			...requestInit,
			['method']: 'PUT',
			['body']: encryptedData,
		},
	);

	if (!response.ok) {
		throw new Error('Unexpected response code: ' + response.status);
	}

	return [btoau(new Uint8Array(wrappedEncryptionKey)), btoau(iv)];
};

const deleteFile = async (
	awsClient: AwsClient,
	baseUri: string,
	name: string,
	requestInit?: RequestInit,
): Promise<Response> => {
	return awsClient.fetch(`${baseUri}/${encodeURIComponent(name)}`, {
		...requestInit,
		['method']: 'GET',
	});
};

const decryptFile = async (
	awsClient: AwsClient,
	baseUri: string,
	name: string,
	unwrappingKey: CryptoKey,
	wrappedDecryptionKeyB64: string,
	ivB64: string,
	requestInit?: RequestInit,
): Promise<ArrayBuffer> => {
	const iv = autobb(ivB64);
	const wrappedDecryptionKey = autobb(wrappedDecryptionKeyB64);

	const decryptionKey = await globalThis.crypto.subtle.unwrapKey(
		'raw',
		wrappedDecryptionKey,
		unwrappingKey,
		{ ['name']: 'AES-KW' },
		{
			['name']: 'AES-GCM',
			['length']: 256,
		},
		false,
		['decrypt'],
	);

	const response = await awsClient.fetch(
		`${baseUri}/${encodeURIComponent(name)}`,
		{
			...requestInit,
			['method']: 'GET',
		},
	);

	if (!response.ok) {
		throw new Error('Unexpected response code: ' + response.status);
	}

	const decryptedData = await globalThis.crypto.subtle.decrypt(
		{ ['name']: 'AES-GCM', ['iv']: iv },
		decryptionKey,
		await response.arrayBuffer(),
	);

	return decryptedData;
};

export { decryptFile, deleteFile, encryptFile };
