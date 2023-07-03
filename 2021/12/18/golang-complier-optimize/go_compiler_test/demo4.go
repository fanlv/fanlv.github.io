package main

var counter = 1

func main() {
	go thread1()
	for counter < 2 {
	}
	println("finish , counter = ", counter)
}

func thread1() int {
	k2 := 0
	for k2 < 100 {
		k2 = k2 + 1
	}
	return 1
}
