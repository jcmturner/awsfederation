package main

import (
	"flag"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jcmturner/awsfederation/app"
	"github.com/jcmturner/awsfederation/config"
	"log"
)

func main() {
	configPath := flag.String("config", "./awsfederation-config.json", "Specify the path to the configuration file")
	// Load configuration
	c, err := config.Load(*configPath)
	if err != nil {
		c.ApplicationLogf("failed to configure AWS Federation Server: %v", err)
		log.Fatalf("Failed to configure AWS Federation Server: %v\n", err)
	}
	c.ApplicationLogf(c.Summary())

	// Create the app
	var a app.App
	// Initialise the app
	err = a.Initialize(c)
	if err != nil {
		c.ApplicationLogf("application initialisation error: %v", err)
		log.Fatalf("Application initialisation error: %v\n", err)
	}

	// Run the app
	err = a.Run()
	c.ApplicationLogf("Application exit: %v", err)
	log.Fatalf("Application exit: %v\n", err)
}
