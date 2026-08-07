package logger

import (
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	Logger *log.Entry
)

func init() {
	Logger = NewLogger()
}

// NewLogger creates a new log entry with default settings.
func NewLogger() *log.Entry {
	return log.WithFields(log.Fields{"safeguard_pid": os.Getpid()})
}

func logLevel(level string) string {
	logLevelEnv := os.Getenv("SAFEGUARD_LOG")
	if logLevelEnv != "" {
		return logLevelEnv
	}

	return strings.ToUpper(level)
}

// SetLevel sets the logging level (debug, info, warn, error, fatal).
func SetLevel(level string) {
	level = logLevel(level)

	switch level {
	case "TRACE":
		log.SetLevel(log.TraceLevel)
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

// SetFormatter sets the log output format (text or json).
func SetFormatter(format string) {
	switch format {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	default:
		log.SetFormatter(&log.JSONFormatter{})
	}
}

// SetOutput sets the log output file path.
func SetOutput(path string) {
	if path == "stdout" || path == "" {
		Logger.Logger.Out = os.Stdout
	} else {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			Logger.Fatal(err)
		}
		Logger.Logger.Out = file
	}
}

// SetRotation configures log file rotation with size and age limits.
func SetRotation(path string, maxSize, maxAge int) {
	if path == "stdout" || path == "" {
		return
	}

	log.SetOutput(&lumberjack.Logger{
		Filename: path,
		MaxSize:  maxSize,
		MaxAge:   maxAge,
	})
}

// SetLabel sets persistent labels for all log entries.
func SetLabel(labels map[string]string) {
	for k, v := range labels {
		Logger = Logger.WithFields(log.Fields{k: v})
	}
}

// Fatal logs an error and exits.
func Fatal(err error) {
	Logger.Fatal(err)
}

// Debug logs a debug-level message.
func Debug(message string) {
	Logger.Debug(message)
}

// Info logs an info-level message.
func Info(message string) {
	Logger.Info(message)
}

// Error logs an error-level message.
func Error(err error) {
	Logger.Error(err)
}

// WithFields returns a log entry with additional fields.
func WithFields(fields log.Fields) *log.Entry {
	return log.WithFields(fields)
}

// LogLabels holds persistent labels for log entries.
type LogLabels struct {
	Labels map[string]string
}

// AuditEventLog is the base structure for all audit event logs.
type AuditEventLog struct {
	Module     string
	Action     string
	Hostname   string
	PID        uint32
	UID        uint32
	Comm       string
	ParentComm string
}

// RestrictedNetworkLog represents a network restriction event.
type RestrictedNetworkLog struct {
	AuditEventLog
	Addr     string
	Domain   string
	Port     uint16
	Protocol string
}

// RestrictedFileAccessLog represents a file access restriction event.
type RestrictedFileAccessLog struct {
	AuditEventLog
	Path string
}

// RestrictedMountLog represents a mount restriction event.
type RestrictedMountLog struct {
	AuditEventLog
	SourcePath string
}

// RestrictedProcessLog represents a process restriction event.
type RestrictedProcessLog struct {
	AuditEventLog
	PPID uint32
}

func (l *RestrictedNetworkLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Module":     l.Module,
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"Addr":       l.Addr,
		"Domain":     l.Domain,
		"Port":       l.Port,
		"Protocol":   l.Protocol,
	}).Info("Traffic is trapped in the filter.")
}

func (l *RestrictedFileAccessLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Module":   l.Module,
		"Action":   l.Action,
		"Hostname": l.Hostname,
		"PID":      l.PID,
		"UID":      l.UID,
		"UName": func(UID uint32) string {
			u, err := user.LookupId(strconv.FormatUint(uint64(UID), 10))
			if err != nil {
				return "Nan"
			} else {
				return u.Username
			}
		}(l.UID),
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"Path":       l.Path,
	}).Info("File access is trapped in th filter.")
}

func (l *RestrictedMountLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Module":     l.Module,
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"SourcePath": l.SourcePath,
	}).Info("Mount event is trapped in th filter.")
}

func (l *RestrictedProcessLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Module": l.Module,
		//"Action":   l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"PPID":       l.PPID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
	}).Info("Process event is trapped in th filter.")
}
// test: verify develop branch PR target
