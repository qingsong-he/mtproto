package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/sdidyk/mtproto"
)

func usage() {
	fmt.Print("Telegram is a simple MTProto tool.\n\nUsage:\n\n")
	fmt.Print("    ./telegram <command> [arguments]\n\n")
	fmt.Print("The commands are:\n\n")
	//fmt.Print("    auth  <phone_number>            auth connection by code\n")
	fmt.Print("    auth or authSMS  <phone_number>            auth connection by code\n")
	fmt.Print("    msg   <user_id> <msgtext>       send message to user\n")
	fmt.Print("    list                            get contact list\n")
	fmt.Println()
}

func init() {
	_, zoneOffset := time.Now().Zone()
	zoneOffset = zoneOffset / 3600
	log.SetPrefix("+" + strconv.Itoa(zoneOffset) + " ")
	log.SetFlags(log.Flags() | log.Lshortfile)
}

func main() {
	var err error

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	//commands := map[string]int{"auth": 1, "msg": 2, "list": 0}
	commands := map[string]int{"auth": 1, "authSMS": 1, "msg": 2, "list": 0}
	valid := false
	for k, v := range commands {
		if os.Args[1] == k {
			if len(os.Args) < v+2 {
				usage()
				os.Exit(1)
			}
			valid = true
			break
		}
	}

	if !valid {
		usage()
		os.Exit(1)
	}

	m, err := mtproto.NewMTProto(os.Getenv("HOME") + "/.telegram_go")
	if err != nil {
		//fmt.Printf("Create failed: %s\n", err)
		//os.Exit(2)
		log.Fatalln(err)
	}

	err = m.Connect()
	if err != nil {
		//fmt.Printf("Connect failed: %s\n", err)
		//os.Exit(2)
		log.Fatalln(err)
	}

	switch os.Args[1] {
	case "auth":
		err = m.Auth(os.Args[2], false)
	case "authSMS":
		err = m.Auth(os.Args[2], true)
	case "msg":
		user_id, _ := strconv.Atoi(os.Args[2])
		err = m.SendMessage(int32(user_id), os.Args[3])

	case "list":
		err = m.GetContacts()
	}

	if err != nil {
		//fmt.Println(err)
		//os.Exit(2)
		log.Fatalln(err)
	}
}
