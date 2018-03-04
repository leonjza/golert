package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/gen2brain/dlgs"
	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/logger"
	"github.com/tidwall/gjson"
)

// Result is a raw result received from osquery
type Result struct {
	Name         string `json:"name"`
	CalendarTime string `json:"calendarTime"`
	Action       string `json:"action"`
}

// AlertMessage is a UI definition of the type of alert
// that the user will see as well as the message to send.
type AlertMessage struct {
	Type    AlertType
	Name    string
	Message string
}

// LoggerConfiguration contains configuration options for the logger.
// this is mostly so that we can pass the verbose flag we get from
// the commandline to the LogString() func.
type LoggerConfiguration struct {
	verbose bool
}

// AlertType encodes the type of alert to send.
type AlertType int

const (
	// AlertTypeNotification is merely an OS level alert
	AlertTypeNotification AlertType = iota
	// AlertTypePopup is a popup that should be dismissed
	AlertTypePopup
)

// a global logger configuration instance
var loggerConfiguration = &LoggerConfiguration{}

func main() {

	// osquery passes these flags to the extention
	var (
		socketPath = flag.String("socket", "", "path to osqueryd extensions socket")
		timeout    = flag.Int("timeout", 0, "")
		_          = flag.Int("interval", 0, "")
		verbose    = flag.Bool("verbose", false, "")
	)
	flag.Parse()

	loggerConfiguration.verbose = *verbose

	// make sure the extentions socket is available
	if !extentionSocketIsAvailable(socketPath) {
		log.Fatal("unable to find the extentions socket in time.")
	}

	server, err := osquery.NewExtensionManagerServer(
		"golert_logger_extention",
		*socketPath,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
	)
	if err != nil {
		log.Fatalf("error creating extension: %s\n", err)
	}

	newLogger := logger.NewPlugin("golert", LogString)
	server.RegisterPlugin(newLogger)

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

// LogString logs a string
func LogString(ctx context.Context, typ logger.LogType, logText string) error {

	// results entries (that are of type 'string') are the only
	// ones we are interested in displaying notifications for.
	if typ == logger.LogTypeString {

		result := &Result{}
		json.Unmarshal([]byte(logText), &result)

		message := &AlertMessage{}

		switch result.Name {
		case "pack_hardware_usb_devices":
			message.Type = AlertTypePopup
			message.Name = "USB Device Connection"
			message.Message = fmt.Sprintf("Vendor: %s\nModel: %s\nSerial: %s\n",
				gjson.Get(logText, "columns.vendor"),
				gjson.Get(logText, "columns.model"),
				gjson.Get(logText, "columns.serial"))

		case "pack_network_arp_spoofing":
			message.Type = AlertTypePopup
			message.Name = "Gateway IP / MAC Change"
			message.Message = fmt.Sprintf("Gateway: %s\nMAC Address: %s\n",
				gjson.Get(logText, "columns.gateway"),
				gjson.Get(logText, "columns.mac"))

		case "pack_malware_process_with_rmd_bin":
			message.Type = AlertTypePopup
			message.Name = "Running Process Without Binary on Disk"
			// pid = 50470
			// cmdline = ./pewpew
			// cwd = /Users/pewpew/scratch
			// uid = 501
			// gid = 20
			message.Message = fmt.Sprintf("PID: %s\nCommand line: %s\nCWD: %s\nUID: %s\nGID: %s\n",
				gjson.Get(logText, "columns.pid"),
				gjson.Get(logText, "columns.cmdline"),
				gjson.Get(logText, "columns.cwd"),
				gjson.Get(logText, "columns.uid"),
				gjson.Get(logText, "columns.gid"))

		case "pack_network_macos_listening_ports":
			message.Type = AlertTypePopup
			message.Name = "Process with Listening Port on All Interfaces"
			// pid = 468
			// name = rapportd
			// path = /usr/libexec/rapportd
			// port = 49878
			// protocol = 6
			message.Message = fmt.Sprintf("PID: %s\nName: %s\nPath: %s\nPort: %s\nProtocol: %s\n",
				gjson.Get(logText, "columns.pid"),
				gjson.Get(logText, "columns.name"),
				gjson.Get(logText, "columns.path"),
				gjson.Get(logText, "columns.port"),
				gjson.Get(logText, "columns.protocol"))

		case "pack_network_dns_lookup_for_invalid_name":
			message.Type = AlertTypePopup
			message.Name = "DNS Lookup Successfull for Invalid Domain"
			// response_code =
			// bytes =
			message.Message = fmt.Sprintf("Response Code: %s\nBytes: %s\n",
				gjson.Get(logText, "columns.response_code"),
				gjson.Get(logText, "columns.bytes"))

		default:
			message.Type = AlertTypeNotification
			message.Name = "Alert"
			message.Message = fmt.Sprintf("No Alert Message Defined for: %s\n", result.Name)
		}

		go func(result *Result, message *AlertMessage) {

			switch message.Type {
			case AlertTypeNotification:
				// `tell application "System Events" to display notification "`+message+`" with title "`+title+`" sound name "default"`
				if err := beeep.Alert(message.Name, message.Message, ""); err != nil {
					log.Printf("error sending notification: %s\n", err.Error())
				}

			case AlertTypePopup:
				// `tell application "System Events" to display dialog "`+text+`" with title "`+title+`" buttons {"OK"} default button "OK" with icon `+icon+``
				_, err := dlgs.Warning("Alert!", fmt.Sprintf("%s\n\nAction: %s\nTime: %s\n\n%s",
					message.Name, strings.Title(result.Action), result.CalendarTime, message.Message))
				if err != nil {
					log.Printf("error sending popup: %s\n", err.Error())
				}

			default:
				log.Printf("received message with unknown alert type. message was: %s\n", message.Message)
			}

		}(result, message)
	}

	if loggerConfiguration.verbose {

		log.Printf("[golert] %s: %s\n", typ, logText)
	}

	return nil
}

// check is the osquery extentions socket is available yet.
// we will give the socket a few seconds (20 * 200ms) to become
// available.
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
