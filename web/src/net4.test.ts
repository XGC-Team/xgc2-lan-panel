import { expect, test } from 'vitest';
import { composeCIDR, networkGateway, parsePrefix, splitHostMask } from './net4';

test('parsePrefix accepts slash-length and dotted mask', () => {
  expect(parsePrefix('24')).toBe(24);
  expect(parsePrefix('/24')).toBe(24);
  expect(parsePrefix('255.255.255.0')).toBe(24);
  expect(parsePrefix('255.255.0.0')).toBe(16);
  expect(parsePrefix('255.255.255.128')).toBe(25);
  expect(parsePrefix('255.0.255.0')).toBeNull();
  expect(parsePrefix('33')).toBeNull();
});

test('networkGateway is the first host', () => {
  expect(networkGateway('192.168.100.40', '24')).toBe('192.168.100.1');
  expect(networkGateway('192.168.100.40', '255.255.255.0')).toBe('192.168.100.1');
  expect(networkGateway('10.136.136.130', '16')).toBe('10.136.0.1');
  expect(networkGateway('192.168.100.40', '32')).toBeNull();
});

test('composeCIDR normalizes dotted mask to prefix', () => {
  expect(composeCIDR('192.168.100.40', '255.255.255.0')).toBe('192.168.100.40/24');
});

test('splitHostMask pulls prefix out of a pasted CIDR', () => {
  expect(splitHostMask('192.168.100.40/24')).toEqual({ ip: '192.168.100.40', mask: '24' });
  expect(splitHostMask('192.168.100.40')).toEqual({ ip: '192.168.100.40', mask: '' });
});
