package main

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/gen2brain/beeep"
	"github.com/gen2brain/dlgs"
	"github.com/tidwall/gjson"
)

const (
	alertTypePopup        = "popup"
	alertTypeNotification = "notification"
)

// NotifierConfig contains the values needed to process an alert.
type NotifierConfig struct {
	Name            string `mapstructure:"name"`
	Enabled         bool   `mapstructure:"enabled"`
	Type            string `mapstructure:"type"`
	MessageFormat   string `mapstructure:"message_fmt"`
	Template        string `mapstructure:"template"`
	CompiledMessage string
	Fields          []string `mapstructure:"fields"`
}

// AlertMessage is a UI definition of the type of alert
// that the user will see as well as the message to send.
type AlertMessage struct {
	Type    string
	Time    string
	Name    string
	Message string
	Action  string
}

// compileMessageTemplate will extract the fields required from the log message
// JSON and compile the template as per the configuration file.
func (config *NotifierConfig) compileMessageTemplate(logEntry *string) {

	d := make(map[string]string, len(config.Fields))

	// Resolve the required field values
	for _, field := range config.Fields {
		d[field] = gjson.Get(*logEntry, "columns."+field).String()
	}

	// Compile the template
	buf := &bytes.Buffer{}

	tmpl, err := template.New("golert").Parse(config.Template)
	if err != nil {
		log.Fatal(err)
	}

	if err = tmpl.Execute(buf, d); err != nil {
		log.Fatal(err)
	}

	// Set the compiled message.
	config.CompiledMessage = buf.String()
}

// processLogEntry does the heavy lifting of preparing the correct
// message struct to finally display an alert / popup based on the
// contents of the configuration file.
func processLogEntry(osQuerylogEntry string) {

	// Parse out the main bits of info from the log entry.
	logEntryName := gjson.Get(osQuerylogEntry, "name").String()
	logEntryAction := gjson.Get(osQuerylogEntry, "action").String()
	logEntryCalendarTime := gjson.Get(osQuerylogEntry, "calendarTime").String()

	// Read the notifier configuration
	notifiers := viper.GetStringMap("notifiers")

	if len(notifiers) <= 0 {
		log.Error("no notifier configurations could be found. no alerts will fire.")
		return
	}

	_, exists := notifiers[logEntryName]
	if !exists {

		log.WithFields(logrus.Fields{"notifier": logEntryName}).Warn("Notifier configuration does not exist!")
		return
	}

	c := NotifierConfig{}
	viper.UnmarshalKey("notifiers."+logEntryName, &c)

	if !c.Enabled {
		log.WithFields(logrus.Fields{"name": c.Name}).Warn("Not processing alert as notifier is disabled")
		return
	}

	// Compile the final message
	c.compileMessageTemplate(&osQuerylogEntry)

	// Prepare a message to fire off with the goroutine to popup/alert.
	message := &AlertMessage{
		Action:  logEntryAction,
		Time:    logEntryCalendarTime,
		Type:    c.Type,
		Name:    c.Name,
		Message: c.CompiledMessage,
	}

	go showAlert(message)
}

// showAlert will finally show the correct popup / alert for the event
func showAlert(message *AlertMessage) {

	switch message.Type {
	case alertTypeNotification:
		log.WithFields(logrus.Fields{"type": message.Type, "name": message.Name, "message": message.Message}).Info("Sending notification")
		if err := beeep.Alert(message.Name, message.Message, ""); err != nil {
			log.Printf("error sending notification: %s\n", err.Error())
		}

	case alertTypePopup:
		log.WithFields(logrus.Fields{"type": message.Type, "name": message.Name, "message": message.Message}).Info("Sending popup")
		_, err := dlgs.Warning("Alert!", fmt.Sprintf("%s\n\nAction: %s\nTime: %s\n\n%s",
			message.Name, strings.Title(message.Action), message.Time, message.Message))
		if err != nil {
			log.Printf("error sending popup: %s\n", err.Error())
		}

	default:
		// Attempt to alert that we couldn't handle the type.
		m := fmt.Sprintf("received message with unknown alert type.message was: %s\n", message.Type)
		if err := beeep.Alert(message.Name, m, ""); err != nil {
			log.Error("error sending notification: %s\n", err.Error())
		}
		log.Error(m)
	}
}
