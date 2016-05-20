package main

import (
	"fmt"
	"os"
	"syscall"

	"os/signal"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/codegangsta/cli.v2"

	"github.com/darkcrux/obvious/db"
)

const (
	AppName = "obvious"
	Version = "dev"
	Usage   = "personal secret keeper. *wink *wink"

	DatabaseFlag = "database"
	DebugFlag    = "debug"
)

var (
	DefaultDatabase = os.Getenv("HOME") + "/.obvious"

	termState *terminal.State
)

// flags: --database

// database format:
// {
//   "secrets": {
//	    "name": "encoded secret",
//   }
// }

// obvious list secrets
// obvious put secret {name}
//   -> enter password
//   -> enter secret
//   -> confirm secret

// obvious get secret {name}
//   -> enter password

// obvious delete secret {name}
//   -> enter password

func main() {
	app := cli.NewApp()
	app.Name = AppName
	app.Usage = Usage
	app.Version = Version
	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   DatabaseFlag,
			Value:  DefaultDatabase,
			Usage:  "path to the secrets file",
			EnvVar: "OBVIOUS_DATABASE",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:   "list",
			Usage:  "list all secrets",
			Action: listSecrets,
		},
		{
			Name:      "put",
			Usage:     "put a secret to the database",
			Action:    putSecret,
			ArgsUsage: "secret-name",
		},
		{
			Name:      "get",
			Usage:     "get a secret from the database",
			Action:    getSecret,
			ArgsUsage: "secret-name",
		},
		{
			Name:   "delete",
			Usage:  "delete a secret from the database",
			Action: deleteSecret,
		},
	}

	enableSafeExit()

	app.Run(os.Args)
	cleanup()
}

func enableSafeExit() {
	var err error
	termState, err = terminal.MakeRaw(0)
	if err != nil {
		panic(err)
	}
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		os.Exit(1)
	}()
}

func cleanup() {
	fmt.Println("=====done=====")
	terminal.Restore(0, termState)
}

func beforeCommand(c *cli.Context) (key []byte, err error) {
	database := c.String(DatabaseFlag)
	// check if db exists
	var password []byte
	if _, err := os.Stat(database); os.IsNotExist(err) {
		password, err = createNewDatabase(database)
		if err != nil {
			return nil, err
		}
	} else {
		fmt.Print("Enter password: ")
		password, err = terminal.ReadPassword(syscall.Stdin)
		fmt.Println()
		if err != nil {
			fmt.Println("Unable to get password: ", err)
			return nil, err
		}
	}
	return password, nil
}

func listSecrets(c *cli.Context) error {
	key, err := beforeCommand(c)
	if err != nil {
		return err
	}
	database := c.String(DatabaseFlag)
	secrets, err := db.List(key, database)
	if err != nil {
		fmt.Println("Unable to list secrets", err)
		cleanup()
		return cli.NewExitError("Unable to list secrets", 1)
	}
	fmt.Println("Secrets:")
	for _, secret := range secrets {
		fmt.Println(" - " + secret)
	}
	return nil
}

func putSecret(c *cli.Context) error {
	key, err := beforeCommand(c)
	if err != nil {
		return err
	}
	database := c.String(DatabaseFlag)
	secretName := c.Args().First()
	fmt.Print("Enter secret: ")
	secret, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		fmt.Println("Unable to read password", err)
		cleanup()
		return cli.NewExitError("Unable to read password", 1)
	}
	err = db.Put(key, database, secretName, secret)
	if err != nil {
		cleanup()
		return cli.NewExitError("Unable to put secret to database", 1)
	}
	return nil
}

func getSecret(c *cli.Context) error {
	key, err := beforeCommand(c)
	if err != nil {
		return err
	}
	database := c.String(DatabaseFlag)
	secretName := c.Args().First()
	secret, err := db.Get(key, database, secretName)
	if err != nil {
		fmt.Println("Unable to get secret", err)
		cleanup()
		return cli.NewExitError("Unable to get secret", 1)
	}
	if err := clipboard.WriteAll(string(secret)); err != nil {
		fmt.Println("Unable to copy secret to clipboard", err)
		cleanup()
		return cli.NewExitError("Unable to copy secret to clipboard", 1)
	}

	fmt.Println("secret copied to clipboard.")
	return nil
}

func deleteSecret(c *cli.Context) error {
	if _, err := beforeCommand(c); err != nil {
		return err
	}
	fmt.Println("delete secret")
	return nil
}

func createNewDatabase(database string) (password []byte, err error) {
	fmt.Printf("Creating database at %s...\n", database)
	fmt.Print("Enter new password: ")
	p, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		fmt.Println("error retrieving password")
		return
	}
	fmt.Print("Confirm new password: ")
	c, err := terminal.ReadPassword(syscall.Stdin)
	fmt.Println()
	if err != nil {
		fmt.Println("error confirming password")
		return
	}
	if string(p) != string(c) {
		fmt.Println("Invalid. Password does not match.")
		err = fmt.Errorf("password does not match\n")
		return
	}
	password = p

	emptyDatabase := &db.FileDatabase{map[string][]byte{}}
	err = db.Save(password, database, emptyDatabase)

	return
}
