package backend

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// PackageManager abstracts system package installation across distributions.
// Gatekeeper needs external software (dnsmasq, wireguard-tools, nftables, etc.)
// and this interface lets us install it on any supported platform without
// hardcoding package manager commands throughout the codebase.
type PackageManager interface {
	// Name returns the package manager identifier (e.g. "apk", "apt", "pkg").
	Name() string
	// Install installs one or more packages. Idempotent — already-installed
	// packages are silently skipped.
	Install(packages ...string) error
	// IsInstalled returns true if the named package is installed.
	IsInstalled(pkg string) bool
	// EnsureDeps installs all Gatekeeper runtime dependencies for the
	// current platform. Returns the list of packages that were installed.
	EnsureDeps() (installed []string, err error)
}

// gatekeeperDeps maps canonical dependency names to per-distro package names.
// The key is the canonical name; values are overrides for specific package managers.
var gatekeeperDeps = []depMapping{
	{canonical: "nftables", overrides: map[string]string{"pkg": "nftables"}},
	{canonical: "dnsmasq", overrides: nil},
	{canonical: "wireguard-tools", overrides: map[string]string{"apt": "wireguard-tools", "apk": "wireguard-tools", "dnf": "wireguard-tools", "pacman": "wireguard-tools", "pkg": "wireguard"}},
	{canonical: "sqlite3", overrides: map[string]string{"apk": "sqlite", "pacman": "sqlite", "pkg": "sqlite3"}},
	{canonical: "curl", overrides: nil},
	{canonical: "conntrack", overrides: map[string]string{"apt": "conntrack", "apk": "conntrack-tools", "dnf": "conntrack-tools", "pacman": "conntrack-tools", "pkg": "libnetfilter_conntrack"}},
}

type depMapping struct {
	canonical string
	overrides map[string]string // pkg-manager-name → distro-specific package name
}

// pkgName returns the distro-specific package name for a given package manager.
func (d depMapping) pkgName(pm string) string {
	if d.overrides != nil {
		if name, ok := d.overrides[pm]; ok {
			return name
		}
	}
	return d.canonical
}

// DetectPackageManager auto-detects the system package manager.
func DetectPackageManager() (PackageManager, error) {
	if runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" {
		return &bsdPkg{}, nil
	}

	// Linux: detect from /etc/os-release or binary presence.
	distro := detectLinuxDistro()
	switch distro {
	case "alpine":
		return &apkPM{}, nil
	case "debian", "ubuntu", "raspbian", "linuxmint", "pop":
		return &aptPM{}, nil
	case "fedora", "rhel", "centos", "rocky", "alma":
		return &dnfPM{}, nil
	case "arch", "manjaro", "endeavouros":
		return &pacmanPM{}, nil
	case "gentoo":
		return &emergePM{}, nil
	case "opensuse", "sles":
		return &zypperPM{}, nil
	case "void":
		return &xbpsPM{}, nil
	default:
		// Fall back to binary detection.
		for _, pm := range []struct {
			bin string
			fn  func() PackageManager
		}{
			{"apk", func() PackageManager { return &apkPM{} }},
			{"apt-get", func() PackageManager { return &aptPM{} }},
			{"dnf", func() PackageManager { return &dnfPM{} }},
			{"pacman", func() PackageManager { return &pacmanPM{} }},
			{"emerge", func() PackageManager { return &emergePM{} }},
			{"zypper", func() PackageManager { return &zypperPM{} }},
			{"xbps-install", func() PackageManager { return &xbpsPM{} }},
			{"pkg", func() PackageManager { return &bsdPkg{} }},
		} {
			if _, err := exec.LookPath(pm.bin); err == nil {
				return pm.fn(), nil
			}
		}
		return nil, fmt.Errorf("no supported package manager found on %s", runtime.GOOS)
	}
}

// detectLinuxDistro reads /etc/os-release to identify the distribution.
func detectLinuxDistro() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			id = strings.Trim(id, `"`)
			return strings.ToLower(id)
		}
	}
	return ""
}

// runPM executes a package manager command and logs the result.
func runPM(name string, args ...string) error {
	slog.Info("package manager", "cmd", name, "args", args)
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// checkBinary returns true if a binary is in PATH.
func checkBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// --- Alpine (apk) ---

type apkPM struct{}

func (p *apkPM) Name() string { return "apk" }

func (p *apkPM) Install(packages ...string) error {
	args := append([]string{"add", "--no-cache"}, packages...)
	return runPM("apk", args...)
}

func (p *apkPM) IsInstalled(pkg string) bool {
	cmd := exec.Command("apk", "info", "-e", pkg)
	return cmd.Run() == nil
}

func (p *apkPM) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// --- Debian/Ubuntu (apt) ---

type aptPM struct{ updated bool }

func (p *aptPM) Name() string { return "apt" }

func (p *aptPM) Install(packages ...string) error {
	if !p.updated {
		if err := runPM("apt-get", "update", "-qq"); err != nil {
			slog.Warn("apt-get update failed, proceeding anyway", "error", err)
		}
		p.updated = true
	}
	args := append([]string{"install", "-y", "-qq"}, packages...)
	return runPM("apt-get", args...)
}

func (p *aptPM) IsInstalled(pkg string) bool {
	cmd := exec.Command("dpkg", "-s", pkg)
	return cmd.Run() == nil
}

func (p *aptPM) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// --- Fedora/RHEL (dnf) ---

type dnfPM struct{}

func (p *dnfPM) Name() string { return "dnf" }

func (p *dnfPM) Install(packages ...string) error {
	args := append([]string{"install", "-y"}, packages...)
	return runPM("dnf", args...)
}

func (p *dnfPM) IsInstalled(pkg string) bool {
	cmd := exec.Command("rpm", "-q", pkg)
	return cmd.Run() == nil
}

func (p *dnfPM) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// --- Arch (pacman) ---

type pacmanPM struct{}

func (p *pacmanPM) Name() string { return "pacman" }

func (p *pacmanPM) Install(packages ...string) error {
	args := append([]string{"-S", "--noconfirm", "--needed"}, packages...)
	return runPM("pacman", args...)
}

func (p *pacmanPM) IsInstalled(pkg string) bool {
	cmd := exec.Command("pacman", "-Qi", pkg)
	return cmd.Run() == nil
}

func (p *pacmanPM) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// --- Gentoo (emerge) ---

type emergePM struct{}

func (p *emergePM) Name() string { return "emerge" }

func (p *emergePM) Install(packages ...string) error {
	args := append([]string{"--noreplace"}, packages...)
	return runPM("emerge", args...)
}

func (p *emergePM) IsInstalled(pkg string) bool {
	cmd := exec.Command("equery", "list", pkg)
	return cmd.Run() == nil
}

func (p *emergePM) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// --- openSUSE (zypper) ---

type zypperPM struct{}

func (p *zypperPM) Name() string { return "zypper" }

func (p *zypperPM) Install(packages ...string) error {
	args := append([]string{"install", "-y"}, packages...)
	return runPM("zypper", args...)
}

func (p *zypperPM) IsInstalled(pkg string) bool {
	cmd := exec.Command("rpm", "-q", pkg)
	return cmd.Run() == nil
}

func (p *zypperPM) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// --- Void (xbps) ---

type xbpsPM struct{}

func (p *xbpsPM) Name() string { return "xbps" }

func (p *xbpsPM) Install(packages ...string) error {
	args := append([]string{"-Sy"}, packages...)
	return runPM("xbps-install", args...)
}

func (p *xbpsPM) IsInstalled(pkg string) bool {
	cmd := exec.Command("xbps-query", pkg)
	return cmd.Run() == nil
}

func (p *xbpsPM) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// --- FreeBSD/BSD (pkg) ---

type bsdPkg struct{}

func (p *bsdPkg) Name() string { return "pkg" }

func (p *bsdPkg) Install(packages ...string) error {
	args := append([]string{"install", "-y"}, packages...)
	return runPM("pkg", args...)
}

func (p *bsdPkg) IsInstalled(pkg string) bool {
	cmd := exec.Command("pkg", "info", pkg)
	return cmd.Run() == nil
}

func (p *bsdPkg) EnsureDeps() ([]string, error) {
	return ensureDepsGeneric(p)
}

// ensureDepsGeneric installs all missing Gatekeeper dependencies using
// the detected package manager.
func ensureDepsGeneric(pm PackageManager) ([]string, error) {
	var missing []string
	for _, dep := range gatekeeperDeps {
		pkg := dep.pkgName(pm.Name())
		if !pm.IsInstalled(pkg) {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		slog.Info("all dependencies already installed")
		return nil, nil
	}
	slog.Info("installing missing dependencies", "packages", missing)
	if err := pm.Install(missing...); err != nil {
		return nil, fmt.Errorf("install dependencies: %w", err)
	}
	return missing, nil
}
