package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Cerebral-Systems/capsule/internal/control"
)

func sessionCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("session requires a subcommand: create, accept, message, share, approve, revoke, export")
	}
	switch args[0] {
	case "create":
		return sessionCreate(args[1:])
	case "accept":
		return sessionAccept(args[1:])
	case "message":
		return sessionMessage(args[1:])
	case "share":
		return sessionShare(args[1:])
	case "approve":
		return sessionApprove(args[1:])
	case "revoke":
		return sessionRevoke(args[1:])
	case "export":
		return sessionExport(args[1:])
	default:
		return fmt.Errorf("unknown session command %q", args[0])
	}
}

func sessionCreate(args []string) error {
	fs := flag.NewFlagSet("session create", flag.ContinueOnError)
	capsuleID := fs.String("capsule", "", "capsule opening the session")
	task := fs.String("task", "", "issue or task the session is for")
	ttl := fs.String("ttl", "1h", "session lifetime, or 0 for no expiry")
	var allow multiFlag
	var allowExec multiFlag
	fs.Var(&allow, "allow", "workspace path this capsule may share; repeatable")
	fs.Var(&allowExec, "allow-exec", "command this capsule may run during the session; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dur, err := parseTTL(*ttl)
	if err != nil {
		return err
	}
	client, err := openClient()
	if err != nil {
		return err
	}
	sess, err := client.CreateSession(context.Background(), control.CreateSessionRequest{
		CapsuleID: *capsuleID,
		Task:      *task,
		Allow:     allow,
		AllowExec: allowExec,
		TTL:       dur,
	})
	if sess.ID != "" {
		fmt.Println(sess.ID)
	}
	return err
}

func sessionAccept(args []string) error {
	fs := flag.NewFlagSet("session accept", flag.ContinueOnError)
	capsuleID := fs.String("capsule", "", "capsule joining the session")
	var allow multiFlag
	var allowExec multiFlag
	fs.Var(&allow, "allow", "workspace path this capsule may share; repeatable")
	fs.Var(&allowExec, "allow-exec", "command this capsule may run during the session; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("session accept requires a session id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	sess, err := svc.AcceptSession(context.Background(), fs.Arg(0), *capsuleID, allow, allowExec)
	if err != nil {
		return err
	}
	fmt.Println(sess.ID)
	return nil
}

func sessionMessage(args []string) error {
	fs := flag.NewFlagSet("session message", flag.ContinueOnError)
	from := fs.String("from", "", "capsule id sending the message")
	text := fs.String("text", "", "message text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("session message requires a session id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	sess, err := svc.MessageSession(context.Background(), fs.Arg(0), *from, *text)
	if err != nil {
		return err
	}
	fmt.Println(sess.ID)
	return nil
}

func sessionShare(args []string) error {
	fs := flag.NewFlagSet("session share", flag.ContinueOnError)
	from := fs.String("from", "", "capsule id sharing the file")
	path := fs.String("path", "", "workspace-relative path to share")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("session share requires a session id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	sess, err := svc.ShareSession(context.Background(), fs.Arg(0), *from, *path)
	if err != nil {
		return err
	}
	fmt.Println(sess.ID)
	return nil
}

func sessionApprove(args []string) error {
	fs := flag.NewFlagSet("session approve", flag.ContinueOnError)
	by := fs.String("by", "", "capsule id granting the approval")
	action := fs.String("action", "", "action to approve, such as \"share logs/failure.txt\"")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("session approve requires a session id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	sess, err := svc.ApproveSession(context.Background(), fs.Arg(0), *by, *action)
	if err != nil {
		return err
	}
	fmt.Println(sess.ID)
	return nil
}

func sessionRevoke(args []string) error {
	if len(args) != 1 {
		return errors.New("session revoke requires a session id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	sess, err := svc.RevokeSession(context.Background(), args[0])
	if err != nil {
		return err
	}
	fmt.Println(sess.ID)
	return nil
}

func sessionExport(args []string) error {
	if len(args) != 1 {
		return errors.New("session export requires a session id")
	}
	svc, err := openClient()
	if err != nil {
		return err
	}
	sess, err := svc.ExportSession(context.Background(), args[0])
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(sess)
}

func parseTTL(value string) (time.Duration, error) {
	if value == "0" {
		return 0, nil
	}
	dur, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid --ttl %q", value)
	}
	return dur, nil
}
