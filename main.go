package main

import (
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jcmturner/awsfederation/app"
	"github.com/jcmturner/awsfederation/config"
	"log"
	"os"
)

func main() {
	version := flag.Bool("version", false, "Print version information")
	dbInit := flag.Bool("dbinit", false, "Initialise the database schema and tables")
	dbInitAdminUser := flag.String("dbinit-adminuser", "root", "The database admin username for initial database deployment")
	dbInitAdminPasswd := flag.String("dbinit-adminpasswd", "", "The database admin user password for initial database deployment")
	dbInitSocket := flag.String("dbinit-dbsocket", "", "The socket to connect to the database over TCP (format <IP>:<PORT>)")
	configPath := flag.String("config", "./awsfederation-config.json", "Specify the path to the configuration file.")
	flag.Parse()

	// Print version information and exit.
	if *version {
		v, bh, bt := app.Version()
		fmt.Fprintf(os.Stderr, "AWS Federation Version Information:\nVersion:\t%s\nBuild hash:\t%s\nBuild time:\t%v\n", v, bh, bt)
		os.Exit(0)
	}

	// Load configuration
	c, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to configure AWS Federation Server: %v\n", err)
	}
	c.ApplicationLogf(c.Summary())

	// Initialise the database.
	if *dbInit {
		dbinit(c, dbInitSocket, dbInitAdminUser, dbInitAdminPasswd)
	}

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

func dbinit(c *config.Config, dbInitSocket, dbInitAdminUser, dbInitAdminPasswd *string) {
	l := log.New(os.Stderr, "AWS Federation DB Init: ", log.Ldate|log.Ltime)
	l.Println("AWS Federation database initialisation underway.")
	if *dbInitSocket == "" {
		l.Println("Database connection socket not provided.")
		l.Fatalln("Database Initialisation FAILED")
	}
	if *dbInitAdminPasswd == "" {
		l.Println("Password for the database admin user not provided.")
		l.Fatalln("Database Initialisation FAILED")
	}
	l.Printf("Connecting to database: %s\n", *dbInitSocket)
	l.Printf("Connecting as: %s\n", *dbInitAdminUser)
	err := app.ApplyDBSchema(c, *dbInitSocket, *dbInitAdminUser, *dbInitAdminPasswd)
	if err != nil {
		l.Printf("Error initialising database:\n---\n%v\n---\n", err)
		l.Fatalln("Database Initialisation FAILED")
	}
	l.Println("Database Initialisation SUCCESSFUL")
	os.Exit(0)
}
