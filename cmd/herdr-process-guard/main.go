package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Efeguclu1/herdr-process-guard/internal/guard"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/presentation"
	"github.com/Efeguclu1/herdr-process-guard/internal/ui"
)

const version = "0.2.1"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "process-guard:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "dashboard"
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}
	if command == "version" || command == "--version" {
		fmt.Println("herdr-process-guard", version)
		return nil
	}
	if command == "help" || command == "--help" || command == "-h" {
		printHelp()
		return nil
	}
	if handled, err := watchdogCommand(command, args); handled {
		return err
	}
	engine, err := guard.New()
	if err != nil {
		return err
	}
	switch command {
	case "dashboard":
		return ui.Run(engine)
	case "scan":
		jsonOutput := hasFlag(args, "--json")
		report, err := engine.Scan("scan")
		if err != nil {
			return err
		}
		return printReport(report, jsonOutput)
	case "snapshot":
		reason := flagValue(args, "--reason", "event")
		_, err := engine.Scan(reason)
		return err
	case "explain":
		pid, err := requiredPID(args)
		if err != nil {
			return err
		}
		report, err := engine.Scan("explain")
		if err != nil {
			return err
		}
		tree, err := engine.FindTree(report, pid)
		if err != nil {
			return err
		}
		if hasFlag(args, "--json") {
			return printJSON(tree)
		}
		fmt.Print(presentation.Tree(*tree))
		return nil
	case "mark-intentional":
		pid, err := requiredPID(args)
		if err != nil {
			return err
		}
		tree, err := engine.MarkIntentional(pid)
		if err != nil {
			return err
		}
		fmt.Printf("Marked exact live tree rooted at PID %d intentional; approval expires when it exits.\n", tree.RootPID)
		return nil
	case "unmark-intentional":
		pid, err := requiredPID(args)
		if err != nil {
			return err
		}
		if err := engine.UnmarkIntentional(pid); err != nil {
			return err
		}
		fmt.Printf("Removed intentional mark for PID %d.\n", pid)
		return nil
	case "stop":
		return stopCommand(engine, args, false)
	case "force":
		return stopCommand(engine, args, true)
	default:
		printHelp()
		return fmt.Errorf("unknown command %q", command)
	}
}

func printHelp() {
	fmt.Print(`Herdr Process Guard

Usage:
  herdr-process-guard dashboard
  herdr-process-guard scan [--json]
  herdr-process-guard explain <pid> [--json]
  herdr-process-guard stop <pid> [--dry-run] [--json]
  herdr-process-guard force <pid> [--dry-run] [--json]
  herdr-process-guard mark-intentional <pid>
  herdr-process-guard unmark-intentional <pid>
  herdr-process-guard snapshot --reason <event>
  herdr-process-guard watch [--config <path>]
  herdr-process-guard watch-once [--config <path>]
  herdr-process-guard watchdog-status [--json]
  herdr-process-guard watchdog-report
  herdr-process-guard watchdog-dashboard
  herdr-process-guard watchdog-config
  herdr-process-guard pause | resume
  herdr-process-guard service-install | service-start | service-stop
  herdr-process-guard service-status | service-ensure | service-uninstall

Stopping is interactive. There is deliberately no --yes flag.
`)
}

func requiredPID(args []string) (int, error) {
	for _, value := range args {
		if strings.HasPrefix(value, "-") {
			continue
		}
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 0 {
			return 0, fmt.Errorf("invalid pid %q", value)
		}
		return pid, nil
	}
	return 0, errors.New("a pid is required")
}

func stopCommand(engine *guard.Engine, args []string, force bool) error {
	pid, err := requiredPID(args)
	if err != nil {
		return err
	}
	plan, err := engine.PlanStop(pid, force)
	if err != nil {
		return err
	}
	jsonOutput, dryRun := hasFlag(args, "--json"), hasFlag(args, "--dry-run")
	if jsonOutput {
		if err := printJSON(plan); err != nil {
			return err
		}
	} else {
		fmt.Print(presentation.StopPlan(plan))
	}
	if dryRun {
		return nil
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("termination requires an interactive terminal; use --dry-run for noninteractive preview")
	}
	required := fmt.Sprintf("stop %d", pid)
	if force {
		required = fmt.Sprintf("force %d", pid)
	}
	fmt.Printf("Type %q to continue: ", required)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != required {
		return errors.New("confirmation did not match; nothing was signaled")
	}
	result, err := engine.ExecuteStop(plan)
	if err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(result)
	}
	if len(result.Survivors) > 0 {
		fmt.Printf("%s sent; %d process(es) survived. Review with `force %d --dry-run`.\n", result.Signal, len(result.Survivors), pid)
	} else {
		fmt.Printf("%s completed; all selected processes exited.\n", result.Signal)
	}
	return nil
}

func hasFlag(args []string, name string) bool {
	for _, value := range args {
		if value == name {
			return true
		}
	}
	return false
}
func flagValue(args []string, name, fallback string) string {
	for i, value := range args {
		if value == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return fallback
}
func printReport(report model.Report, jsonOutput bool) error {
	if jsonOutput {
		return printJSON(report)
	}
	fmt.Print(presentation.Report(report))
	return nil
}
func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
