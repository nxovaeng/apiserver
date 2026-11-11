package logger

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/natefinch/lumberjack.v2"

	"xray-panel-server/internal/config"
)

// Level represents log level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarning
	LevelError
)

var (
	currentLevel Level = LevelInfo
	debugLogger        = log.New(os.Stdout, "[DEBUG] ", log.LstdFlags|log.Lshortfile)
	infoLogger         = log.New(os.Stdout, "[INFO]  ", log.LstdFlags)
	warnLogger         = log.New(os.Stdout, "[WARN]  ", log.LstdFlags)
	errorLogger        = log.New(os.Stdout, "[ERROR] ", log.LstdFlags|log.Lshortfile)
)

// Init initializes the logger with configuration.
func Init(cfg *config.LogConfig) error {
	currentLevel = parseLevel(cfg.Level)

	writers := []io.Writer{os.Stdout}

	if cfg.File != "" {
		dir := filepath.Dir(cfg.File)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		fileWriter := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		}
		writers = append(writers, fileWriter)
	}

	multiWriter := io.MultiWriter(writers...)

	debugLogger = log.New(multiWriter, "[DEBUG] ", log.LstdFlags|log.Lshortfile)
	infoLogger = log.New(multiWriter, "[INFO]  ", log.LstdFlags)
	warnLogger = log.New(multiWriter, "[WARN]  ", log.LstdFlags)
	errorLogger = log.New(multiWriter, "[ERROR] ", log.LstdFlags|log.Lshortfile)

	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags)

	Debug("Logger initialized with level: %s", cfg.Level)
	if cfg.File != "" {
		Debug("Logging to file: %s", cfg.File)
	}

	return nil
}

func parseLevel(level string) Level {
	switch strings.ToLower(level) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warning", "warn":
		return LevelWarning
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func Debug(format string, v ...interface{}) {
	if currentLevel <= LevelDebug {
		debugLogger.Printf(format, v...)
	}
}

func Info(format string, v ...interface{}) {
	if currentLevel <= LevelInfo {
		infoLogger.Printf(format, v...)
	}
}

func Warn(format string, v ...interface{}) {
	if currentLevel <= LevelWarning {
		warnLogger.Printf(format, v...)
	}
}

func Error(format string, v ...interface{}) {
	if currentLevel <= LevelError {
		errorLogger.Printf(format, v...)
	}
}

func Fatal(format string, v ...interface{}) {
	errorLogger.Fatalf(format, v...)
}

func SetLevel(level string) {
	currentLevel = parseLevel(level)
	Info("Log level changed to: %s", level)
}

func GetLevel() string {
	switch currentLevel {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarning:
		return "warning"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}
