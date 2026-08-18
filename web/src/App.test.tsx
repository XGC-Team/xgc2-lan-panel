import { render, screen } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { App } from './App';

class FakeEventSource {
  static last: FakeEventSource | undefined;
  onerror: ((event: Event) => void) | null = null;
  readonly listeners = new Map<string, Array<(event: MessageEvent) => void>>();
  constructor(public url: string) {
    FakeEventSource.last = this;
  }
  addEventListener(type: string, handler: (event: MessageEvent) => void) {
    const list = this.listeners.get(type) ?? [];
    list.push(handler);
    this.listeners.set(type, list);
  }
  close() {}
  emit(type: string, data: unknown) {
    for (const handler of this.listeners.get(type) ?? []) {
      handler({ data: JSON.stringify(data) } as MessageEvent);
    }
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
  FakeEventSource.last = undefined;
});

function stubWatch() {
  vi.stubGlobal('EventSource', FakeEventSource);
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: true,
    json: async () => [],
  })));
}

test('empty state when no robots', async () => {
  stubWatch();
  render(<App />);
  FakeEventSource.last?.emit('robots', []);
  expect(await screen.findByText('还没有发现机器人')).toBeInTheDocument();
});

test('renders a discovered robot card', async () => {
  stubWatch();
  render(<App />);
  FakeEventSource.last?.emit('robots', [{
    reach_ip: '192.168.100.40',
    last_seen: new Date().toISOString(),
    stale: false,
    beacon: {
      id: 'abc',
      hostname: 'xavier',
      default_iface: 'wlan1',
      ssh_user: 'agilex',
      ifaces: [{
        name: 'wlan1',
        kind: 'wifi',
        up: true,
        addrs: ['192.168.100.40/24'],
        ssid: 'BIU_5G',
        gateway: '192.168.100.1',
        dns: ['192.168.100.1'],
        is_default: true,
      }],
    },
  }]);
  expect(await screen.findByText('xavier')).toBeInTheDocument();
  expect(screen.getByText('agilex@192.168.100.40')).toBeInTheDocument();
  expect(screen.getByText(/BIU_5G/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: '默认' })).toBeDisabled();
  expect(screen.getByRole('button', { name: '配置' })).toBeInTheDocument();
});
