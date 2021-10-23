package main

import (
	"aes/mycrypto"
	"aes/myerror"
	"flag"
	"fmt"
	"os"
)

func main() {
	mytimer := new(myerror.Mytimer)
	var enPath string
	var dePath string
	var outPath string
	var bufSize int
	var bigFile bool
	flag.StringVar(&enPath, "e", "", "输入目标加密文件路径")
	flag.StringVar(&dePath, "d", "", "输入被加密文件路径")
	flag.StringVar(&outPath, "o", "out.dat", "输入目的文件路径")
	flag.BoolVar(&bigFile, "b", true, "是否开启大文件模式")
	flag.Parse()

	if bigFile {
		fmt.Println("What buffer size do you want? (Must be a multiple of 16)")
		fmt.Scanln(&bufSize)
		if bufSize%16 != 0 {
			fmt.Println("Must be a multiple of 16.")
			os.Exit(0)
		}
	}

	if (enPath == "" && dePath == "") || (enPath != "" && dePath != "") {
		fmt.Println("Wrong parameter, input --help for help.")
		os.Exit(0)
	}

	if enPath != "" {
		var prama string
		var strength int8
		fmt.Println("Do you want to use password generator? (Only 16, 24, 32 bytes type can be generated) [Y/n]")
		pline()
		fmt.Scanln(&prama)
		if prama == "y" || prama == "Y" || prama == "yes" || prama == "" {
			fmt.Printf("(The key can either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256)\nWhich strength do you need? [16/24/32]\n")
			pline()
			fmt.Scanln(&strength)
			if strength == 16 || strength == 24 || strength == 32 {
				if bigFile {
					mytimer.Init()
					key := mycrypto.GenKey(strength)
					mycrypto.BigFileEncrypto(*key, enPath, outPath, bufSize)
					mytimer.Dur()
					fmt.Printf("Please remember your key: "+"<\033[0;32;31m %s \033[0m>"+"\n", key.KeyString())
					fmt.Printf("The output is at: <\033[0;32;31m %s \033[0m>\n", outPath)
					os.Exit(0)
				} else {
					mytimer.Init()
					key := mycrypto.GenKey(strength)
					mycrypto.FileEncrypto(*key, enPath, outPath)
					mytimer.Dur()
					fmt.Printf("Please remember your key: "+"<\033[0;32;31m %s \033[0m>"+"\n", key.KeyString())
					fmt.Printf("The output is at: <\033[0;32;31m %s \033[0m>\n", outPath)
					os.Exit(0)
				}
			} else {
				fmt.Println("Wrong parameter, should be either 16, 24, or 32.")
				os.Exit(0)
			}
		} else if prama != "n" && prama != "N" && prama != "no" {
			fmt.Println("Wrong parameter, input y, Y, yes, n, N, or nothing for Y.")
			os.Exit(0)
		}
	}

	var keyString string
	fmt.Println("Input your key. (Do not input longer than 32 bytes)")
	pline()
	_, err := fmt.Scanln(&keyString)
	myerror.CheckError(err)
	key := mycrypto.MakeKey([]byte(keyString))
	if enPath != "" {
		if bigFile {
			mytimer.Init()
			mycrypto.BigFileEncrypto(*key, enPath, outPath, bufSize)
			mytimer.Dur()
			fmt.Printf("Please remember your key: "+"<\033[0;32;31m %s \033[0m>"+"\n", key.KeyString())
			fmt.Printf("The output is at: <\033[0;32;31m %s \033[0m>\n", outPath)
			os.Exit(0)
		} else {
			mytimer.Init()
			mycrypto.FileEncrypto(*key, enPath, outPath)
			mytimer.Dur()
			fmt.Printf("Please remember your key: "+"<\033[0;32;31m %s \033[0m>"+"\n", key.KeyString())
			fmt.Printf("The output is at: <\033[0;32;31m %s \033[0m>\n", outPath)
			os.Exit(0)
		}
	} else if dePath != "" {
		if bigFile {
			mytimer.Init()
			mycrypto.BigFileDecrypto(*key, dePath, outPath, bufSize)
			mytimer.Dur()
			fmt.Printf("The output is at: <\033[0;32;31m %s \033[0m>\n", outPath)
			os.Exit(0)
		} else {
			mytimer.Init()
			mycrypto.FileDecrypto(*key, dePath, outPath)
			mytimer.Dur()
			fmt.Printf("The output is at: <\033[0;32;31m %s \033[0m>\n", outPath)
			os.Exit(0)
		}
	} else {
		fmt.Println("Wrong parameter, input --help for help.")
		os.Exit(0)
	}
	os.Exit(0)
}
