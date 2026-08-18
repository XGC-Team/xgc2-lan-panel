package nmapply

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
)

const (
	preferredMetric = 50
	demotedMetric   = 20600
	profilePrefix   = "xgc2-"
)

var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)

// Command is one nmcli invocation. Secret values stay in Args for nmcli
// but must never be logged via String().
type Command struct {
	Args    []string
	Secrets []string
}

func (c Command) String() string {
	out := make([]string, len(c.Args))
	copy(out, c.Args)
	for _, secret := range c.Secrets {
		if secret == "" {
			continue
		}
		for i, a := range out {
			if a == secret {
				out[i] = "***"
			}
		}
	}
	return "nmcli " + strings.Join(out, " ")
}

type Plan struct {
	Commands []Command
	Warning  string
}

type Runner func(args []string) (string, error)

func Validate(req protocol.ApplyRequest) error {
	if !ifaceNameRe.MatchString(req.Iface) {
		return fmt.Errorf("invalid iface")
	}
	if req.SSID != "" && len(req.SSID) > 32 {
		return fmt.Errorf("ssid too long")
	}
	if req.Address != "" {
		ip, ipnet, err := net.ParseCIDR(req.Address)
		if err != nil || ip.To4() == nil || ipnet == nil {
			return fmt.Errorf("address must be IPv4 CIDR")
		}
	}
	if req.Gateway != "" && net.ParseIP(req.Gateway).To4() == nil {
		return fmt.Errorf("gateway must be IPv4")
	}
	for _, d := range req.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("dns must be IP")
		}
	}
	if req.SSID == "" && req.Address == "" && !req.MakeDefault {
		return fmt.Errorf("nothing to apply")
	}
	return nil
}

func ProfileName(iface string) string {
	return profilePrefix + iface
}

// BuildPlan constructs nmcli steps. activeByIface maps iface -> NM connection name.
func BuildPlan(req protocol.ApplyRequest, kind string, activeByIface map[string]string) (Plan, error) {
	if err := Validate(req); err != nil {
		return Plan{}, err
	}
	if kind == "" {
		kind = "wifi"
		if !strings.HasPrefix(req.Iface, "wl") && !strings.HasPrefix(req.Iface, "wlan") {
			kind = "ethernet"
		}
	}
	profile := ProfileName(req.Iface)
	var cmds []Command
	if req.SSID != "" {
		if kind != "wifi" {
			return Plan{}, fmt.Errorf("ssid is only valid on wifi ifaces")
		}
		cmds = append(cmds, Command{Args: []string{"connection", "delete", profile}})
		add := []string{
			"connection", "add", "type", "wifi",
			"ifname", req.Iface,
			"con-name", profile,
			"ssid", req.SSID,
			"connection.interface-name", req.Iface,
			"connection.autoconnect", "yes",
			"connection.autoconnect-priority", "100",
		}
		cmds = append(cmds, Command{Args: add})
		if req.Password != "" {
			cmds = append(cmds, Command{
				Args: []string{
					"connection", "modify", profile,
					"wifi-sec.key-mgmt", "wpa-psk",
					"wifi-sec.psk", req.Password,
				},
				Secrets: []string{req.Password},
			})
		} else {
			cmds = append(cmds, Command{Args: []string{
				"connection", "modify", profile,
				"wifi-sec.key-mgmt", "none",
			}})
		}
		if old := activeByIface[req.Iface]; old != "" && old != profile {
			cmds = append(cmds, Command{Args: []string{
				"connection", "modify", old,
				"connection.autoconnect", "no",
			}})
		}
	} else if activeByIface[req.Iface] == "" {
		return Plan{}, fmt.Errorf("iface %s has no active connection; provide ssid", req.Iface)
	} else {
		profile = activeByIface[req.Iface]
	}

	if req.Address != "" {
		mod := []string{
			"connection", "modify", profile,
			"ipv4.method", "manual",
			"ipv4.addresses", req.Address,
			"ipv4.ignore-auto-dns", "yes",
			"connection.interface-name", req.Iface,
			"connection.autoconnect", "yes",
		}
		if req.Gateway != "" {
			mod = append(mod, "ipv4.gateway", req.Gateway)
		}
		if len(req.DNS) > 0 {
			mod = append(mod, "ipv4.dns", strings.Join(req.DNS, ","))
		}
		cmds = append(cmds, Command{Args: mod})
	}

	if req.MakeDefault {
		cmds = append(cmds, Command{Args: []string{
			"connection", "modify", profile,
			"ipv4.route-metric", fmt.Sprintf("%d", preferredMetric),
			"ipv4.never-default", "no",
		}})
		seen := map[string]bool{profile: true}
		for iface, name := range activeByIface {
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			if iface == req.Iface {
				continue
			}
			cmds = append(cmds, Command{Args: []string{
				"connection", "modify", name,
				"ipv4.route-metric", fmt.Sprintf("%d", demotedMetric),
			}})
		}
	}

	cmds = append(cmds, Command{Args: []string{"connection", "up", profile}})
	plan := Plan{Commands: cmds}
	if req.SSID != "" || req.Address != "" {
		plan.Warning = "applying on the NIC you are talking through may drop this session; the robot should reappear with the new address"
	}
	return plan, nil
}

func ParseActiveConnections(nmcliShow string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(nmcliShow, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		name, dev := parts[0], parts[1]
		if dev == "" || name == "" {
			continue
		}
		out[dev] = name
	}
	return out
}

func Run(run Runner, plan Plan) error {
	for i, cmd := range plan.Commands {
		if _, err := run(cmd.Args); err != nil {
			if i == 0 && len(cmd.Args) >= 3 && cmd.Args[1] == "delete" {
				continue
			}
			return fmt.Errorf("%s: %w", cmd.String(), err)
		}
	}
	return nil
}
