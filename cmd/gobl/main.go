// Command gobl is a fail2ban action that keeps temporary and permanent
// bans in nftables sets, with per-IP history in SQLite and optional
// permaban sharing between hosts through Redis.
package main

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
	"strings"
	"time"

	"github.com/madkox/gobl/internal/config"
)

var version = "dev"

const usage = `usage: gobl [-c config] [-v] <command> [args]

fail2ban actions:
  init                 create missing sets, restore permabans from the DB
  flush                flush the temp sets
  ban <ip> [--jail n] [--restored 0|1]
                       record a ban and add <ip> to the temp or perm set;
                       restored bans (fail2ban restart) are not counted again
  unban <ip>           remove <ip> from the temp set

scheduled:
  maintain             decay, forgive, sync perm sets with the DB
  sync                 sync permabans through Redis (if redis_url is set)

operator tools:
  show <ip>            show the record for <ip>
  list [--perm]        list records
  pardon <ip>          lift a ban (temp and perm) and forget the history
  import-yaml <file>   import a list.yml from rubl
  check-config [file]  validate a config file (exit 1 if invalid)
  version              print the version
`

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

type logger struct {
	sys     *syslog.Writer
	stderr  io.Writer
	verbose bool
}

func newLogger(verbose, useSyslog bool) *logger {
	l := &logger{stderr: os.Stderr, verbose: verbose}
	if useSyslog {
		if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "gobl"); err == nil {
			l.sys = w
		}
	}
	return l
}

// Info goes to syslog, and to stderr only with -v.
func (l *logger) Info(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if l.sys != nil {
		l.sys.Info(msg)
	}
	if l.verbose {
		fmt.Fprintln(l.stderr, msg)
	}
}

// Warn goes to syslog and stderr.
func (l *logger) Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if l.sys != nil {
		l.sys.Warning(msg)
	}
	fmt.Fprintln(l.stderr, "gobl: "+msg)
}

// Error goes to syslog and stderr.
func (l *logger) Error(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if l.sys != nil {
		l.sys.Err(msg)
	}
	fmt.Fprintln(l.stderr, "gobl: error: "+msg)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cfgPath := config.DefaultPath
	if p := os.Getenv("GOBL_CONFIG"); p != "" {
		cfgPath = p
	}
	verbose := false

	// Global flags come before the command.
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch {
		case args[0] == "-v":
			verbose = true
			args = args[1:]
		case args[0] == "-c" && len(args) > 1:
			cfgPath = args[1]
			args = args[2:]
		case strings.HasPrefix(args[0], "-c="):
			cfgPath = strings.TrimPrefix(args[0], "-c=")
			args = args[1:]
		case args[0] == "-h" || args[0] == "--help":
			fmt.Print(usage)
			return exitOK
		default:
			fmt.Fprintf(os.Stderr, "gobl: unknown flag %s\n%s", args[0], usage)
			return exitUsage
		}
	}
	if len(args) == 0 || args[0] == "" {
		fmt.Fprint(os.Stderr, "No action selected, doing nothing...\n"+usage)
		return exitUsage
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Println("gobl", version)
		return exitOK
	case "check-config":
		return cmdCheckConfig(rest, cfgPath)
	}

	cfg, err := config.Load(cfgPath)
	log := newLogger(verbose, cfg.Syslog)
	if err != nil {
		// Keep going with what could be parsed plus defaults: a broken
		// config must never stop a ban.
		log.Error("config %s: %v (continuing with defaults for invalid values)", cfgPath, err)
	}
	a := &app{cfg: cfg, log: log, now: func() int64 { return time.Now().Unix() }}

	pos, flags := splitArgs(rest)
	switch cmd {
	case "init":
		return a.cmdInit()
	case "flush":
		return a.cmdFlush()
	case "ban":
		if len(pos) < 1 {
			return exitUsage
		}
		return a.cmdBan(pos[0], flags["jail"], flags["restored"] == "1")
	case "unban":
		if len(pos) < 1 {
			return exitUsage
		}
		return a.cmdUnban(pos[0], flags["jail"])
	case "maintain":
		return a.cmdMaintain()
	case "sync":
		return a.cmdSync()
	case "show":
		if len(pos) < 1 {
			return exitUsage
		}
		return a.cmdShow(pos[0])
	case "list":
		_, perm := flags["perm"]
		return a.cmdList(perm)
	case "pardon":
		if len(pos) < 1 {
			return exitUsage
		}
		return a.cmdPardon(pos[0])
	case "import-yaml":
		if len(pos) < 1 {
			return exitUsage
		}
		return a.cmdImportYAML(pos[0])
	default:
		fmt.Fprintf(os.Stderr, "Unknown action %q\n%s", cmd, usage)
		return exitUsage
	}
}

// splitArgs separates positional arguments from --name value / --name=value
// flags. Unknown flags are kept but ignored by commands, so fail2ban action
// files can pass extra arguments without breaking older binaries.
func splitArgs(args []string) (pos []string, flags map[string]string) {
	flags = map[string]string{}
	valued := map[string]bool{"jail": true, "restored": true}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			pos = append(pos, arg)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !hasVal && valued[name] && i+1 < len(args) {
			i++
			val = args[i]
		}
		flags[name] = val
	}
	return pos, flags
}

func cmdCheckConfig(args []string, defPath string) int {
	path := defPath
	if len(args) > 0 {
		path = args[0]
	}
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "gobl: %v\n", err)
		return exitError
	}
	if _, err := config.Load(path); err != nil {
		fmt.Fprintf(os.Stderr, "gobl: %s: %v\n", path, err)
		return exitError
	}
	fmt.Printf("%s: ok\n", path)
	return exitOK
}
