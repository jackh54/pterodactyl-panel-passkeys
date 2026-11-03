import { describe, expect, it } from 'vitest';
import { fromB64url, safeIntended, toB64url } from './passkeys';

describe('safeIntended', () => {
    it.each([
        ['/', '/'],
        ['/oauth/authorize?client_id=x', '/oauth/authorize?client_id=x'],
        ['//evil.example', '/'],
        ['/\\evil.example', '/'],
        ['https://evil.example/', '/'],
        ['javascript:alert(1)', '/'],
        [undefined, '/'],
        [42, '/'],
    ])('%s -> %s', (input, expected) => {
        expect(safeIntended(input)).toBe(expected);
    });
});

describe('base64url', () => {
    it('round-trips bytes without padding or + and /', () => {
        const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 0x00, 0x01]);
        const encoded = toB64url(bytes.buffer);
        expect(encoded).toBe('-__-AAE');
        expect(new Uint8Array(fromB64url(encoded))).toEqual(bytes);
        expect(toB64url(null)).toBe('');
    });
});
