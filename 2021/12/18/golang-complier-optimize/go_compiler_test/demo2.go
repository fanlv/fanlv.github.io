package main

var counter = 1
var flag = true

func main() {
	go thread1()
	for counter < 2 {
	}
	println("finish , counter =", counter)
}

func thread1() {
	for flag {
		counter++
	}
}
