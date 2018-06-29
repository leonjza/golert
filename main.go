package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/logger"
	"github.com/spf13/viper"
)

// LoggerConfiguration contains configuration options for the logger.
// this is mostly so that we can pass the verbose flag we get from
// the commandline to the LogString() func.
type LoggerConfiguration struct {
	verbose bool
}

var log = logrus.New()

// a global logger configuration instance
var loggerConfiguration = &LoggerConfiguration{}

// check is the osquery extentions socket is available yet.
// we will give the socket a few seconds (20 * 200ms) to become available.
func extentionSocketIsAvailable(socketPath *string) bool {

	var count int

	for count < 20 {

		if _, err := os.Stat(*socketPath); os.IsNotExist(err) {

			time.Sleep(time.Millisecond * 200)
			count++
			continue
		}
		return true
	}

	return false
}

func main() {

	cwd, _ := os.Executable()
	cwd = filepath.Dir(cwd)

	// osquery passes these flags to the extention
	var (
		socketPath = flag.String("socket", "", "path to osqueryd extensions socket")
		timeout    = flag.Int("timeout", 0, "")
		_          = flag.Int("interval", 0, "")
		verbose    = flag.Bool("verbose", false, "")
		configFile = flag.String("config", cwd, "path to the golert configuration file")
	)
	flag.Parse()

	loggerConfiguration.verbose = *verbose

	// Configuration
	viper.SetConfigName("golert")
	viper.AddConfigPath(*configFile)
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatalln(fmt.Errorf("fatal error config file: %s", err))
	}

	// Add live configuration watching for notifier changes
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.WithFields(logrus.Fields{"name": e.Name}).Info("Config file changed and reloaded")
	})

	// Check if a file path is specified for golert to log
	logfilePath := viper.GetString("logfile")

	if logfilePath != "" {
		file, err := os.OpenFile(logfilePath, os.O_CREATE|os.O_WRONLY, 0666)
		if err == nil {
			log.Out = file
		} else {
			log.Error("Failed to log to file, using default stderr")
			log.Out = os.Stdout
		}
	}

	// make sure the extentions socket is available
	if !extentionSocketIsAvailable(socketPath) {
		log.Fatal("unable to find the extentions socket in time.")
	}

	server, err := osquery.NewExtensionManagerServer(
		"golert-logger", *socketPath,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
	)
	if err != nil {
		log.Fatalf("error creating extension: %s\n", err)
	}

	newLogger := logger.NewPlugin("golert-logger", LogString)
	server.RegisterPlugin(newLogger)

	log.Info("Starting golert")
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

// LogString logs a string
func LogString(ctx context.Context, typ logger.LogType, logText string) error {

	// results entries (that are of type 'string') are the only
	// ones we are interested in displaying notifications for.
	if typ == logger.LogTypeString {

		processLogEntry(logText)

	} else {

		log.WithFields(logrus.Fields{"log-type": typ}).Warn("Got an unprocessable logtype")
	}

	if loggerConfiguration.verbose {

		log.WithFields(logrus.Fields{"log-type": typ, "log-text": logText}).Info("Logentry")
	}

	return nil
}
