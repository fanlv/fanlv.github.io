# Golang Memory Model


## 一、背景

### 1.1 一个CodeReview引发的思考
一个同学在我们 `Golang` 项目里面用 `Double Check`（不清楚的同学可以去百度搜下Java中比较常见，Golang底层Sync库也有部分代码用到这种方式）的方式实现了一个单例。具体实现如下：
	
	var instance *UserInfo
	
	func getInstance() (*UserInfo, error) {
		if instance == nil {
			//---Lock
			lock.Lock()
			defer lock.Unlock()
			if instance == nil {
				a := &UserInfo{
					Name: "fan",
				}
				instance = a
			}
		}//---Unlock()
		return instance, nil
	}


这个代码第一眼看上去好像是标准的`Double Check`的写法，确没有什么问题。但是用 `go run -race go_race2.go` 检查会报下面警告：

	==================
	WARNING: DATA RACE
	Read at 0x00000120d9c0 by goroutine 8:
	  main.getInstance()
	      /Users/hh/go/src/github.com/hh/GolangDemo/GoTest/go_race2.go:42 +0x4f
	  main.main.func1()
	      /Users/hh/go/src/github.com/hh/GolangDemo/GoTest/go_race2.go:24 +0x44
	
	Previous write at 0x00000120d9c0 by goroutine 7:
	  main.getInstance()
	      /Users/hh/go/src/github.com/hh/GolangDemo/GoTest/go_race2.go:49 +0x169
	  main.main.func1()
	      /Users/hh/go/src/github.com/hh/GolangDemo/GoTest/go_race2.go:24 +0x44
	
	Goroutine 8 (running) created at:
	  main.main()
	      /Users/hh/go/src/github.com/hh/GolangDemo/GoTest/go_race2.go:23 +0xab
	
	Goroutine 7 (finished) created at:
	  main.main()
	      /Users/hh/go/src/github.com/hh/GolangDemo/GoTest/go_race2.go:23 +0xab
	==================


警告中指明在多线程执行`getInstance`这个方法的时候，在`if instance == nil {` 这一行会发生`data race`。具体为什么发生`data race`这个涉及到 `Memory Model`这个概念。



### 1.2 什么是 Memory Model

很多同学第一次听到这个单词的时候，潜意识翻译成中文就是`内存模型`，好像是讲的一个数据结构相关的东西。某度上搜索`Memory Model`出来更多是不相干东西。我们看下[wikipedia](https://en.wikipedia.org/wiki/Memory_model_(programming)#:~:text=In%20computing%2C%20a%20memory%20model,shared%20use%20of%20the%20data.)上的解释：

> In computing, a memory model describes the interactions of threads through memory and their shared use of the data.

直接翻译过来就是：`在程序运行中，内存模型描述了多线程如何通过内存的交互来共享数据`

**`Memory Model` 其实是一个概念，表示在多线程场景下，如何保证数据同步的正确性。** 为什么多线程读取共享内存变量的时候会有`数据同步正确性`问题呢，这里主要涉及到`CPU乱序执行`，

各个语言对`Memory Model`实现方式各不相同，对其他语言感兴趣的同学可以去搜索下相关资料。

[Java Memory Model](https://en.wikipedia.org/wiki/Java_memory_model) 

[C++ Memory Model](https://en.cppreference.com/w/cpp/language/memory_model#:~:text=Defines%20the%20semantics%20of%20computer,memory%20has%20a%20unique%20address.) 

[《C++ Concurrency in Action》第五章](https://book.douban.com/subject/27036085/) （大佬推荐的书，耐何精力有限，还没拜读）


##
