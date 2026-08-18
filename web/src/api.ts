export type Iface = {
  name: string;
  mac?: string;
  kind: string;
  up: boolean;
  addrs?: string[];
  ssid?: string;
  gateway?: string;
  dns?: string[];
  metric?: number;
  is_default: boolean;
  signal_dbm?: number | null;
};

export type Robot = {
  beacon: {
    id: string;
    hostname: string;
    default_iface?: string;
    ssh_user?: string;
    users?: string[];
    ifaces: Iface[];
  };
  reach_ip: string;
  last_seen: string;
  stale: boolean;
};

export type ApplyRequest = {
  iface: string;
  ssid?: string;
  password?: string;
  address?: string;
  gateway?: string;
  dns?: string[];
  make_default?: boolean;
};

export type ApplyResult = {
  ok?: boolean;
  gone?: boolean;
  message?: string;
  warning?: string;
};

const apiBase = '';

export async function fetchRobots(): Promise<Robot[]> {
  const res = await fetch(`${apiBase}/api/robots`);
  if (!res.ok) throw new Error(`robots ${res.status}`);
  return res.json() as Promise<Robot[]>;
}

export type WatchHandlers = {
  onRobots: (robots: Robot[]) => void;
  onError?: (message: string) => void;
};

/** Open only while the page is actually being viewed. Close = leave presence. */
export function watchRobots(handlers: WatchHandlers): () => void {
  const source = new EventSource(`${apiBase}/api/watch`);
  source.addEventListener('robots', (event) => {
    try {
      handlers.onRobots(JSON.parse(event.data) as Robot[]);
    } catch {
      handlers.onError?.('机器人列表无法解析');
    }
  });
  source.onerror = () => {
    if (source.readyState === EventSource.CLOSED) {
      handlers.onError?.('观看连接已断开');
    }
  };
  return () => source.close();
}

export async function applyRobot(id: string, body: ApplyRequest): Promise<ApplyResult> {
  const res = await fetch(`${apiBase}/api/robots/${encodeURIComponent(id)}/apply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: ApplyResult = {};
  try {
    parsed = text ? JSON.parse(text) as ApplyResult : {};
  } catch {
    parsed = { message: text || res.statusText };
  }
  if (res.status === 409 || parsed.gone) {
    return {
      ok: false,
      gone: true,
      message: parsed.message || '回拨已过时，已从面板清掉这台车',
    };
  }
  if (!res.ok && res.status !== 502) {
    throw new Error(parsed.message || `apply ${res.status}`);
  }
  if (res.status === 502) {
    return {
      ok: false,
      message: parsed.message || '连接中断，多半是车正在切网',
      warning: parsed.warning || '等几秒，列表里应出现新地址',
    };
  }
  return parsed;
}
