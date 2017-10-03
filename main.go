package main

import (
	"fmt"
	"Ekalit/ekalit"
)

func main()  {
	ekt := ekalit.NewEkalit();
	if ekt.IsConnected() {
		str := ekt.EkalitGetUID()
		fmt.Println(str)
		cert := ekt.ReadCertificate("0000")
		fmt.Println(cert)
		fmt.Println(ekt.EkalitGetErrorCode())
		fmt.Println(ekt.EkalitGetError())
		fmt.Println("True")
	} else {
		str := ekt.EkalitGetUID()
		fmt.Println(str)
		fmt.Println(ekt.EkalitGetErrorCode())
		fmt.Println(ekt.EkalitGetErrorCode())
		fmt.Println("False")
	}
}