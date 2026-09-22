package main

import (
	"github.com/drydock-updater/drydock/cmd"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetLevel(log.InfoLevel)
}

func main() {
	cmd.Execute()
}
