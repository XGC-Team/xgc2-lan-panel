import type { ReactNode } from 'react';
import { useEffect, useMemo, useState } from 'react';
import {
  AppShell,
  Button,
  Checkbox,
  DescriptionItem,
  DescriptionList,
  Drawer,
  EmptyState,
  FormField,
  Inline,
  Input,
  Notice,
  Panel,
  ProductBrand,
  ResponsiveGrid,
  SelectMenu,
  SettingRow,
  SettingsList,
  Stack,
  StatusText,
  Topbar,
} from '@xgc2/ui-react';
import { applyRobot, fetchRobots, watchRobots, type ApplyRequest, type Iface, type Robot } from './api';
import { composeCIDR, networkGateway, splitHostMask } from './net4';

type Draft = {
  iface: string;
  ssid: string;
  password: string;
  address: string;
  mask: string;
  gateway: string;
  dns: string;
  makeDefault: boolean;
};

const emptyDraft: Draft = {
  iface: '',
  ssid: '',
  password: '',
  address: '',
  mask: '24',
  gateway: '',
  dns: '',
  makeDefault: true,
};

export function App() {
  const [robots, setRobots] = useState<Robot[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [editing, setEditing] = useState<Robot | null>(null);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const syncWatch = () => {
      if (document.visibilityState !== 'visible') {
        return undefined;
      }
      setError('');
      return watchRobots({
        onRobots: (next) => {
          setRobots(next);
          setError('');
        },
        onError: (message) => setError(message),
      });
    };
    let stop = syncWatch();
    const onVisibility = () => {
      stop?.();
      stop = undefined;
      if (document.visibilityState === 'visible') {
        stop = syncWatch();
      } else {
        setRobots([]);
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      stop?.();
    };
  }, []);

  const openConfig = (robot: Robot, ifaceName?: string) => {
    const iface = pickIface(robot, ifaceName);
    setEditing(robot);
    setDraft(draftFromIface(iface));
    setNotice('');
  };

  const submit = async () => {
    if (!editing) return;
    setBusy(true);
    setNotice('');
    const cidr = composeCIDR(draft.address, draft.mask);
    if (draft.address.trim() && !cidr) {
      setNotice('静态 IP 或掩码无效。掩码可以是 24 或 255.255.255.0');
      setBusy(false);
      return;
    }
    const req: ApplyRequest = {
      iface: draft.iface,
      ssid: draft.ssid.trim(),
      password: draft.password,
      address: cidr ?? '',
      gateway: draft.gateway.trim(),
      dns: draft.dns.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean),
      make_default: draft.makeDefault,
    };
    try {
      const result = await applyRobot(editing.beacon.id, req);
      if (result.gone) {
        const id = editing.beacon.id;
        setRobots((current) => current.filter((row) => row.beacon.id !== id));
        setEditing(null);
        setNotice(result.message || '回拨已过时，已从面板清掉这台车');
        return;
      }
      setNotice(result.warning || result.message || '已提交');
      if (result.ok) {
        setDraft((current) => ({ ...current, password: '' }));
      }
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const setDefault = async (robot: Robot, iface: string) => {
    setBusy(true);
    try {
      const result = await applyRobot(robot.beacon.id, { iface, make_default: true });
      if (result.gone) {
        setRobots((current) => current.filter((row) => row.beacon.id !== robot.beacon.id));
        setEditing(null);
        setNotice(result.message || '回拨已过时，已从面板清掉这台车');
        return;
      }
      setNotice(result.warning || result.message || '已把默认路由切到该网卡');
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AppShell
      data-xgc-id="lan-panel-shell"
      topbar={
        <Topbar
          brand={<ProductBrand product="LAN Panel" />}
          actions={
            <Button
              appearance="ghost"
              disabled={busy}
              onClick={() => {
                void fetchRobots().then(setRobots).catch((err: unknown) => {
                  setError(err instanceof Error ? err.message : String(err));
                });
              }}
            >
              刷新
            </Button>
          }
        />
      }
    >
      <Stack gap="comfortable">
        <Notice heading="现场网段发现">
          打开本页时，探针对每个本机网段询问；车上单播回拨网卡、SSID、地址、网关和 DNS。可把某一张卡写成固定 Wi-Fi + 静态 IP，并指定默认网卡，避免关键流量走弱网卡。
        </Notice>
        {error ? <Notice tone="danger" heading="探针连不上">{error}</Notice> : null}
        {notice ? <Notice heading="最近一次操作">{notice}</Notice> : null}
        {robots.length === 0 ? (
          <EmptyState
            title="还没有发现机器人"
            description="在车上启动 sudo xgc2-lan-panel beacon。车必须已经连上与地面站相同的某个网段；关页即停询问。"
          />
        ) : (
          <ResponsiveGrid columnWidth="wide" gap="comfortable">
            {robots.map((robot) => (
              <RobotCard
                key={robot.beacon.id}
                robot={robot}
                busy={busy}
                onConfigure={openConfig}
                onDefault={setDefault}
              />
            ))}
          </ResponsiveGrid>
        )}
      </Stack>
      {editing ? (
        <Drawer
          title={`固定连接 · ${editing.beacon.hostname}`}
          description="SSID、密码、静态地址会写成 NetworkManager 配置并绑定到所选网卡，重启后仍走这张卡。"
          onClose={() => setEditing(null)}
          dirty={Boolean(draft.password)}
          footer={
            <Inline justify="end">
              <Button appearance="ghost" onClick={() => setEditing(null)}>取消</Button>
              <Button tone="primary" appearance="solid" disabled={busy || !draft.iface} onClick={() => void submit()}>
                写入并连接
              </Button>
            </Inline>
          }
        >
          <ConfigForm robot={editing} draft={draft} onChange={setDraft} />
        </Drawer>
      ) : null}
    </AppShell>
  );
}

function RobotCard({
  robot,
  busy,
  onConfigure,
  onDefault,
}: {
  robot: Robot;
  busy: boolean;
  onConfigure: (robot: Robot, iface?: string) => void;
  onDefault: (robot: Robot, iface: string) => void;
}) {
  const ssh = sshHint(robot);
  return (
    <Panel
      data-xgc-id={`robot-${robot.beacon.id}`}
      title={robot.beacon.hostname}
      actions={
        <Inline gap="compact">
          <StatusText status={robot.stale ? 'stale' : 'live'}>
            {robot.stale ? '暂时听不到' : '在线'}
          </StatusText>
          <Button uiSize="compact" onClick={() => onConfigure(robot)}>固定连接</Button>
        </Inline>
      }
    >
      <Stack gap="default">
        <DescriptionList columns={2} density="compact">
          <DescriptionItem label="可达地址" value={robot.reach_ip} />
          <DescriptionItem label="默认网卡" value={robot.beacon.default_iface || '—'} />
          <DescriptionItem label="SSH" value={ssh} />
          <DescriptionItem label="网卡数" value={String(robot.beacon.ifaces?.length ?? 0)} />
        </DescriptionList>
        <SettingsList>
          {(robot.beacon.ifaces ?? []).map((iface) => (
            <SettingRow
              key={iface.name}
              title={iface.name}
              description={ifaceLine(iface)}
              actions={
                <Inline gap="compact">
                  {iface.is_default ? (
                    <Button className="lan-iface-default-action" uiSize="compact" disabled>
                      默认
                    </Button>
                  ) : (
                    <Button
                      className="lan-iface-default-action"
                      uiSize="compact"
                      disabled={busy || !iface.up}
                      onClick={() => onDefault(robot, iface.name)}
                    >
                      设为默认
                    </Button>
                  )}
                  <Button uiSize="compact" onClick={() => onConfigure(robot, iface.name)}>配置</Button>
                </Inline>
              }
            />
          ))}
        </SettingsList>
      </Stack>
    </Panel>
  );
}

function ConfigForm({
  robot,
  draft,
  onChange,
}: {
  robot: Robot;
  draft: Draft;
  onChange: (draft: Draft) => void;
}) {
  const options = useMemo(
    () => (robot.beacon.ifaces ?? []).map((iface) => ({
      value: iface.name,
      label: `${iface.name} · ${iface.kind}${iface.ssid ? ` · ${iface.ssid}` : ''}`,
    })),
    [robot],
  );
  const set = (patch: Partial<Draft>) => onChange({ ...draft, ...patch });
  const onIface = (value: string) => {
    const iface = (robot.beacon.ifaces ?? []).find((row) => row.name === value);
    onChange(draftFromIface(iface, { ...draft, iface: value, password: '' }));
  };
  const onAddress = (value: string) => {
    onChange(withDerivedRoute({ ...draft, address: value }, value, draft.mask));
  };
  const onMask = (value: string) => {
    onChange(withDerivedRoute({ ...draft, mask: value }, draft.address, value));
  };
  return (
    <Stack gap="default">
      <FormField label="网卡" required>
        <SelectMenu ariaLabel="选择网卡" value={draft.iface} options={options} onValueChange={onIface} fill />
      </FormField>
      <FormField label="SSID" description="无线网卡必填。有线网卡留空，只改静态地址或默认路由。">
        <Input value={draft.ssid} onValueChange={(value) => set({ ssid: value })} autoComplete="off" />
      </FormField>
      <FormField label="Wi-Fi 密码" description="不会出现在广播里，也不会写进探针日志。">
        <Input type="password" value={draft.password} onValueChange={(value) => set({ password: value })} autoComplete="new-password" />
      </FormField>
      <FormField label="静态 IP" description="只填主机地址。若粘贴 192.168.100.40/24，掩码会自动拆出。">
        <Input value={draft.address} onValueChange={onAddress} placeholder="192.168.100.40" autoComplete="off" />
      </FormField>
      <FormField label="掩码" description="两种写法都可以：24 或 255.255.255.0。">
        <Input value={draft.mask} onValueChange={onMask} placeholder="24 或 255.255.255.0" autoComplete="off" />
      </FormField>
      <FormField label="网关" description="由静态 IP 和掩码自动计算，可改。">
        <Input value={draft.gateway} onValueChange={(value) => set({ gateway: value })} placeholder="192.168.100.1" />
      </FormField>
      <FormField label="DNS" description="默认跟网关相同，可改。多个地址用逗号或空格分开。">
        <Input value={draft.dns} onValueChange={(value) => set({ dns: value })} placeholder="192.168.100.1" />
      </FormField>
      <Checkbox
        checked={draft.makeDefault}
        onCheckedChange={(checked) => set({ makeDefault: checked })}
        label="设为默认网卡（压低其它卡的路由 metric）"
      />
    </Stack>
  );
}

function pickIface(robot: Robot, name?: string): Iface | undefined {
  const ifaces = robot.beacon.ifaces ?? [];
  if (name) return ifaces.find((row) => row.name === name);
  return ifaces.find((row) => row.is_default) ?? ifaces[0];
}

function draftFromIface(iface?: Iface, base: Draft = emptyDraft): Draft {
  const raw = iface?.addrs?.[0] ?? '';
  const split = splitHostMask(raw);
  const next: Draft = {
    ...base,
    iface: iface?.name ?? base.iface,
    ssid: iface?.ssid ?? '',
    address: split.ip,
    mask: split.mask || base.mask || '24',
    makeDefault: true,
  };
  return withDerivedRoute(next, next.address, next.mask);
}

function withDerivedRoute(draft: Draft, ipRaw: string, maskRaw: string): Draft {
  const split = splitHostMask(ipRaw);
  const address = split.ip;
  const mask = split.mask || maskRaw;
  const gateway = networkGateway(address, mask);
  if (!gateway) {
    return { ...draft, address, mask };
  }
  return { ...draft, address, mask, gateway, dns: gateway };
}

function ifaceLine(iface: Iface): ReactNode {
  const bits = [
    iface.kind,
    iface.ssid,
    iface.addrs?.[0],
    iface.gateway ? `gw ${iface.gateway}` : '',
    iface.dns?.[0] ? `dns ${iface.dns[0]}` : '',
    iface.signal_dbm != null ? `${iface.signal_dbm} dBm` : '',
  ].filter(Boolean);
  return bits.join(' · ') || '无地址';
}

function sshHint(robot: Robot): string {
  const user = robot.beacon.ssh_user;
  const def = (robot.beacon.ifaces ?? []).find((row) => row.is_default);
  const ip = def?.addrs?.[0]?.split('/')[0] || robot.reach_ip;
  return user ? `${user}@${ip}` : ip;
}
