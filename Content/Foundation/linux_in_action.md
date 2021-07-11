- [Linux内核技术实战](#linux内核技术实战)
	- [Page Cache](#page-cache)
		- [什么是 Page Cache？](#什么是-page-cache)
		- [为什么需要 Page Cache？](#为什么需要-page-cache)
		- [Page Cache 是如何“诞生”的？](#page-cache-是如何诞生的)
		- [Page Cache 是如何“死亡”/回收的？](#page-cache-是如何死亡回收的)
		- [如何处理Page Cache难以回收产生的load飙高问题？](#如何处理page-cache难以回收产生的load飙高问题)
		- [如何释放PageCache](#如何释放pagecache)
		- [内核机制引起 Page Cache 被回收而产生的业务性能下降](#内核机制引起-page-cache-被回收而产生的业务性能下降)
		- [如何避免 Page Cache 被回收而引起的性能问题？](#如何避免-page-cache-被回收而引起的性能问题)
	- [内存篇](#内存篇)
		- [进程的地址空间](#进程的地址空间)
		- [CPU寻址过程](#cpu寻址过程)
		- [用数据观察进程的内存](#用数据观察进程的内存)
		- [Shmem](#shmem)
		- [OOM Kill方式](#oom-kill方式)
		- [内核内存](#内核内存)
	- [TCP](#tcp)
		- [TCP 连接的建立过程会受哪些配置项的影响？](#tcp-连接的建立过程会受哪些配置项的影响)
		- [TCP 连接的断开过程会受哪些配置项的影响？](#tcp-连接的断开过程会受哪些配置项的影响)
		- [TCP 数据包的发送过程会受什么影响？](#tcp-数据包的发送过程会受什么影响)
		- [TCP 数据包的接收过程会受什么影响？](#tcp-数据包的接收过程会受什么影响)
	- [CPU](#cpu)
		- [CPU 是如何选择线程执行的 ？](#cpu-是如何选择线程执行的-)
		- [TOP 指标](#top-指标)
		- [strace 原理](#strace-原理)
  
# Linux内核技术实战

## Page Cache

### 什么是 Page Cache？

![image.png](https://upload-images.jianshu.io/upload_images/12321605-c13331b6d58f8471.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


通过这张图片你可以清楚地看到，红色的地方就是 Page Cache，很明显，Page Cache 是内核管理的内存，也就是说，它属于内核不属于用户。

	$ cat /proc/meminfo
	...
	Buffers:            1224 kB
	Cached:           111472 kB
	SwapCached:        36364 kB
	Active:          6224232 kB
	Inactive:         979432 kB
	Active(anon):    6173036 kB
	Inactive(anon):   927932 kB
	Active(file):      51196 kB
	Inactive(file):    51500 kB
	...
	Shmem:             10000 kB
	...
	SReclaimable:      43532 kB
	...



> 	Buffers + Cached + SwapCached = Active(file) + Inactive(file) + Shmem + SwapCached

那么等式两边的内容就是我们平时说的 Page Cache。请注意你没有看错，两边都有 SwapCached，之所以要把它放在等式里，就是说它也是 Page Cache 的一部分。

在 Page Cache 中，Active(file)+Inactive(file) 是 File-backed page（与文件对应的内存页），是你最需要关注的部分。因为你平时用的 mmap() 内存映射方式和 buffered I/O 来消耗的内存就属于这部分，最重要的是，这部分在真实的生产环境上也最容易产生问题，我们在接下来的课程案例篇会重点分析它。
	
而 SwapCached 是在打开了 Swap 分区后，把 Inactive(anon)+Active(anon) 这两项里的匿名页给交换到磁盘（swap out），然后再读入到内存（swap in）后分配的内存。由于读入到内存后原来的 Swap File 还在，所以 SwapCached 也可以认为是 File-backed page，即属于 Page Cache。这样做的目的也是为了减少 I/O。你是不是觉得这个过程有些复杂？我们用一张图直观地看一下：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-e4b65848024e1f73.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


除了 SwapCached，Page Cache 中的 Shmem 是指匿名共享映射这种方式分配的内存（free 命令中 shared 这一项），比如 tmpfs（临时文件系统），这部分在真实的生产环境中产生的问题比较少，不是我们今天的重点内容，我们这节课不对它做过多关注，你知道有这回事就可以了。


	$ free -k
	              total        used        free      shared  buff/cache   available
	Mem:        7926580     7277960      492392       10000      156228      430680
	Swap:       8224764      380748     7844016
	
通过 procfs 源码里面的[proc/sysinfo.c](https://gitlab.com/procps-ng/procps/-/blob/master/proc/sysinfo.c)这个文件，你可以发现 buff/cache 包括下面这几项：

> buff/cache = Buffers + Cached + SReclaimable

从这个公式中，你能看到 free 命令中的 buff/cache 是由 Buffers、Cached 和 SReclaimable 这三项组成的，它强调的是内存的可回收性，也就是说，可以被回收的内存会统计在这一项。

其中 SReclaimable 是指可以被回收的内核内存，包括 dentry 和 inode 等。而这部分内容是内核非常细节性的东西，对于应用开发者和运维人员理解起来相对有些难度，所以我们在这里不多说。



我相信有这样想法的人不在少数，如果不用内核管理的 Page Cache，那有两种思路来进行处理：

* 第一种，应用程序维护自己的 Cache 做更加细粒度的控制，比如 MySQL 就是这样做的，你可以参考MySQL Buffer Pool ，它的实现复杂度还是很高的。对于大多数应用而言，实现自己的 Cache 成本还是挺高的，不如内核的 Page Cache 来得简单高效。
* 第二种，直接使用 Direct I/O 来绕过 Page Cache，不使用 Cache 了，省的去管它了。这种方法可行么？那我们继续用数据说话，看看这种做法的问题在哪儿？

### 为什么需要 Page Cache？

	//1.  先生成一个 1G 的文件：
	dd if=/dev/zero of=/home/yafang/test/dd.out bs=4096 count=((1024*256))
	dd if=/dev/zero of=big_file count=10 bs=1G
	
	//2. 其次，清空 Page Cache，需要先执行一下 sync 来将脏页同步到磁盘再去 drop cache。
	$ sync && echo 3 > /proc/sys/vm/drop_caches
	
	// 第一次读取文件的耗时如下：
	$ time cat /home/yafang/test/dd.out &> /dev/null
	real  0m5.733s
	user  0m0.003s
	sys  0m0.213s
	
	// 再次读取文件的耗时如下：
	$ time cat /home/yafang/test/dd.out &> /dev/null 
	real  0m0.132s
	user  0m0.001s
	sys  0m0.130s
	
通过这样详细的过程你可以看到，第二次读取文件的耗时远小于第一次的耗时，这是因为第一次是从磁盘来读取的内容，磁盘 I/O 是比较耗时的，而第二次读取的时候由于文件内容已经在第一次读取时被读到内存了，所以是直接从内存读取的数据，内存相比磁盘速度是快很多的。 **这就是 Page Cache 存在的意义：减少 I/O，提升应用的 I/O 速度** 。


### Page Cache 是如何“诞生”的？

Page Cache 的产生有两种不同的方式：

* Buffered I/O（标准 I/O）；
* Memory-Mapped I/O（存储映射 I/O）。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-159e97bc1103e93c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


标准 I/O 是写的 (write(2)) 用户缓冲区 (Userpace Page 对应的内存)，然后再将用户缓冲区里的数据拷贝到内核缓冲区 (Pagecache Page 对应的内存)；如果是读的 (read(2)) 话则是先从内核缓冲区拷贝到用户缓冲区，再从用户缓冲区读数据，也就是 buffer 和文件内容不存在任何映射关系。

对于存储映射 I/O 而言，则是直接将 Pagecache Page 给映射到用户地址空间，用户直接读写 Pagecache Page 中内容。

显然，存储映射 I/O 要比标准 I/O 效率高一些，毕竟少了“用户空间到内核空间互相拷贝”的过程。这也是很多应用开发者发现，为什么使用内存映射 I/O 比标准 I/O 方式性能要好一些的主要原因。

我们来用具体的例子演示一下 Page Cache 是如何“诞生”的，就以其中的标准 I/O 为例，因为这是我们最常使用的一种方式，如下是一个简单的示例脚本：


    #!/bin/sh

    #这是我们用来解析的文件
    MEM_FILE="/proc/meminfo"

    #这是在该脚本中将要生成的一个新文件
    NEW_FILE="/home/yafang/dd.write.out"

    #我们用来解析的Page Cache的具体项
    active=0
    inactive=0
    pagecache=0

    IFS=' '

    #从/proc/meminfo中读取File Page Cache的大小
    function get_filecache_size()
    {
            items=0
            while read line
            do
                    if [[ "$line" =~ "Active:" ]]; then
                            read -ra ADDR <<<"$line"
                            active=${ADDR[1]}
                            let "items=$items+1"
                    elif [[  "$line" =~ "Inactive:" ]]; then
                            read -ra ADDR <<<"$line"
                            inactive=${ADDR[1]}
                            let "items=$items+1"
                    fi  


                    if [ $items -eq 2 ]; then
                            break;
                    fi  
            done < $MEM_FILE
    }

    #读取File Page Cache的初始大小
    get_filecache_size
    let filecache="$active + $inactive"

    #写一个新文件，该文件的大小为1048576 KB
    dd if=/dev/zero of=$NEW_FILE bs=1024 count=1048576 &> /dev/null

    #文件写完后，再次读取File Page Cache的大小
    get_filecache_size

    #两次的差异可以近似为该新文件内容对应的File Page Cache
    #之所以用近似是因为在运行的过程中也可能会有其他Page Cache产生
    let size_increased="$active + $inactive - $filecache"

    #输出结果
    echo "File size 1048576KB, File Cache increased" $size_inc
    // File size 1048576KB, File Cache increased 1048648KB


通过这个脚本你可以看到，在创建一个文件的过程中，代码中 /proc/meminfo 里的 Active(file) 和 Inactive(file) 这两项会随着文件内容的增加而增加，它们增加的大小跟文件大小是一致的（这里之所以略有不同，是因为系统中还有其他程序在运行）。另外，如果你观察得很仔细的话，你会发现增加的 Page Cache 是 Inactive(File) 这一项。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-079bc645feb0dd8f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


这个过程大致可以描述为：首先往用户缓冲区 buffer(这是 Userspace Page) 写入数据，然后 buffer 中的数据拷贝到内核缓冲区（这是 Pagecache Page），如果内核缓冲区中还没有这个 Page，就会发生 Page Fault 会去分配一个 Page，拷贝结束后该 Pagecache Page 是一个 Dirty Page（脏页），然后该 Dirty Page 中的内容会同步到磁盘，同步到磁盘后，该 Pagecache Page 变为 Clean Page 并且继续存在系统中。


	// 查看账页回写
	$ cat /proc/vmstat | egrep "dirty|writeback"
	nr_dirty 40
	nr_writeback 2

### Page Cache 是如何“死亡”/回收的？

你可以把 Page Cache 的回收行为 (Page Reclaim) 理解为 Page Cache 的“自然死亡”。

	
	$ free -g
	       total  used  free  shared  buff/cache available
	Mem:     125    41     6       0          79        82
	Swap:      0     0     0

free 命令中的 buff/cache 中的这些就是“活着”的 Page Cache，那它们什么时候会“死亡”（被回收）呢？我们来看一张图：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-4e6970042f1ec0dd.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

你可以看到，应用在申请内存的时候，即使没有 free 内存，只要还有足够可回收的 Page Cache，就可以通过回收 Page Cache 的方式来申请到内存，回收的方式主要是两种：直接回收和后台回收。


那它是具体怎么回收的呢？你要怎么观察呢？其实在我看来，观察 Page Cache 直接回收和后台回收最简单方便的方式是使用 sar：

	
	$ sar -B 1
	02:14:01 PM  pgpgin/s pgpgout/s   fault/s  majflt/s  pgfree/s pgscank/s pgscand/s pgsteal/s    %vmeff
	
	
	02:14:01 PM      0.14    841.53 106745.40      0.00  41936.13      0.00      0.00      0.00      0.00
	02:15:01 PM      5.84    840.97  86713.56      0.00  43612.15    717.81      0.00    717.66     99.98
	02:16:01 PM     95.02    816.53 100707.84      0.13  46525.81   3557.90      0.00   3556.14     99.95
	02:17:01 PM     10.56    901.38 122726.31      0.27  54936.13   8791.40      0.00   8790.17     99.99
	02:18:01 PM    108.14    306.69  96519.75      1.15  67410.50  14315.98     31.48  14319.38     99.80
	02:19:01 PM      5.97    489.67  88026.03      0.18  48526.07   1061.53      0.00   1061.42     99.99

* pgscank/s : kswapd(后台回收线程) 每秒扫描的 page 个数。
* pgscand/s: Application 在内存申请过程中每秒直接扫描的 page 个数。
* pgsteal/s: 扫描的 page 中每秒被回收的个数。
* %vmeff: pgsteal/(pgscank+pgscand), 回收效率，越接近 100 说明系统越安全，越接近 0 说明系统内存压力越大。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-294e8ed27891c2b4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


### 如何处理Page Cache难以回收产生的load飙高问题？
大多是有三种情况：

* 直接内存回收引起的 load 飙高；
* 系统中脏页积压过多引起的 load 飙高；
* 系统 NUMA 策略配置不当引起的 load 飙高。


**直接内存回收引起 load 飙高或者业务时延抖动**

直接内存回收是指在进程上下文同步进行内存回收，那么它具体是怎么引起 load 飙高的呢？

因为直接内存回收是在进程申请内存的过程中同步进行的回收，而这个回收过程可能会消耗很多时间，进而导致进程的后续行为都被迫等待，这样就会造成很长时间的延迟，以及系统的 CPU 利用率会升高，最终引起 load 飙高。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-8575b1da6940a9da.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

从图里你可以看到，在开始内存回收后，首先进行后台异步回收（上图中蓝色标记的地方），这不会引起进程的延迟；如果后台异步回收跟不上进程内存申请的速度，就会开始同步阻塞回收，导致延迟（上图中红色和粉色标记的地方，这就是引起 load 高的地址）。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-43588c1eadb08e22.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


那么，针对直接内存回收引起 load 飙高或者业务 RT 抖动的问题，**一个解决方案就是及早地触发后台回收来避免应用程序进行直接内存回收**，那具体要怎么做呢？

它的意思是：当内存水位低于 watermark low 时，就会唤醒 kswapd 进行后台回收，然后 kswapd 会一直回收到 watermark high。

那么，我们可以增大 `min_free_kbytes` 这个配置选项来及早地触发后台回收。

> vm.min_free_kbytes = 4194304

当然了，这样做也有一些缺陷：提高了内存水位后，应用程序可以直接使用的内存量就会减少，这在一定程度上浪费了内存。所以在调整这一项之前，你需要先思考一下，应用程序更加关注什么，如果关注延迟那就适当地增大该值，如果关注内存的使用量那就适当地调小该值。

除此之外，对 CentOS-6(对应于 2.6.32 内核版本) 而言，还有另外一种解决方案：

> vm.extra_free_kbytes = 4194304

那就是将 `extra_free_kbytes` 配置为 4G。`extra_free_kbytes` 在 3.10 以及以后的内核上都被废弃掉了，不过由于在生产环境中还存在大量的机器运行着较老版本内核，你使用到的也可能会是较老版本的内核，所以在这里还是有必要提一下。它的大致原理如下所示：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-0b02d7bedbf200e8.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

`extra_free_kbytes` 的目的是为了解决 min_free_kbyte 造成的内存浪费，但是这种做法并没有被内核主线接收，因为这种行为很难维护会带来一些麻烦，感兴趣的可以看一下这个讨论：add extra free kbytes tunable

总的来说，通过调整内存水位，在一定程度上保障了应用的内存申请，但是同时也带来了一定的内存浪费，因为系统始终要保障有这么多的 free 内存，这就压缩了 Page Cache 的空间。调整的效果你可以通过 /proc/zoneinfo 来观察：

	
	$ egrep "min|low|high" /proc/zoneinfo 
	...
	        min      7019
	        low      8773
	        high     10527
	...

**补充 kswapd0 说明**


除了直接内存回收，还有一个专门的内核线程用来定期回收内存，也就是 kswapd0。为了衡量内存的使用情况，kswapd0 定义了三个内存阈值（watermark，也称为水位），分别是

页最小阈值（pages_min）、页低阈值（pages_low）和页高阈值（pages_high）。剩余内存，则使用 pages_free 表示。

* 剩余内存小于页最小阈值，说明进程可用内存都耗尽了，只有内核才可以分配内存。
* 剩余内存落在页最小阈值和页低阈值中间，说明内存压力比较大，剩余内存不多了。这时 kswapd0 会执行内存回收，直到剩余内存大于高阈值为止。
* 剩余内存落在页低阈值和页高阈值中间，说明内存有一定压力，但还可以满足新内存请求。
* 剩余内存大于页高阈值，说明剩余内存比较多，没有内存压力。

我们可以看到，一旦剩余内存小于页低阈值，就会触发内存的回收。这个页低阈值，其实可以通过内核选项 /proc/sys/vm/min_free_kbytes 来间接设置。min_free_kbytes 设置了页最小阈值，而其他两个阈值，都是根据页最小阈值计算生成的，计算方法如下 ：

	pages_low = pages_min*5/4
	pages_high = pages_min*3/2


![image.png](https://upload-images.jianshu.io/upload_images/12321605-3ba6fe3cc72fb753.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


**系统中脏页过多引起 load 飙高**


接下来，我们分析下由于系统脏页过多引起 load 飙高的情况。在前一个案例中我们也提到，直接回收过程中，如果存在较多脏页就可能涉及在回收过程中进行回写，这可能会造成非常大的延迟，而且因为这个过程本身是阻塞式的，所以又可能进一步导致系统中处于 D 状态的进程数增多，最终的表现就是系统的 load 值很高。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-7387f88156bdbd51.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

那如何解决这类问题呢？**一个比较省事的解决方案是控制好系统中积压的脏页数据**。很多人知道需要控制脏页，但是往往并不清楚如何来控制好这个度，脏页控制的少了可能会影响系统整体的效率，脏页控制的多了还是会触发问题，所以我们接下来看下如何来衡量好这个“度”。

首先你可以通过 sar -r 来观察系统中的脏页个数：

	$ sar -r 1
	07:30:01 PM kbmemfree kbmemused  %memused kbbuffers  kbcached  kbcommit   %commit  kbactive   kbinact   kbdirty
	09:20:01 PM   5681588   2137312     27.34         0   1807432    193016      2.47    534416   1310876         4
	09:30:01 PM   5677564   2141336     27.39         0   1807500    204084      2.61    539192   1310884        20
	09:40:01 PM   5679516   2139384     27.36         0   1807508    196696      2.52    536528   1310888        20
	09:50:01 PM   5679548   2139352     27.36         0   1807516    196624      2.51    536152   1310892        24

至于这些值调整大多少比较合适，也是因系统和业务的不同而异，我的建议也是一边调整一边观察，将这些值调整到业务可以容忍的程度就可以了，即在调整后需要观察业务的服务质量 (SLA)，要确保 SLA 在可接受范围内。调整的效果你可以通过 /proc/vmstat 来查看：

	
	$ grep "nr_dirty_" /proc/vmstat
	nr_dirty_threshold 366998
	nr_dirty_background_threshold 183275
	
	
**系统 NUMA 策略配置不当引起的 load 飙高**

比如说，我们在生产环境上就曾经遇到这样的问题：系统中还有一半左右的 free 内存，但还是频频触发 direct reclaim，导致业务抖动得比较厉害。后来经过排查发现是由于设置了 `zone_reclaim_mode`，这是 NUMA 策略的一种。

设置 `zone_reclaim_mode` 的目的是为了增加业务的 NUMA 亲和性，但是在实际生产环境中很少会有对 NUMA 特别敏感的业务，这也是为什么内核将该配置从默认配置 1 修改为了默认配置 0: mm: disable `zone_reclaim_mode` by default ，配置为 0 之后，就避免了在其他 node 有空闲内存时，不去使用这些空闲内存而是去回收当前 node 的 Page Cache，也就是说，通过减少内存回收发生的可能性从而避免它引发的业务延迟。

那么如何来有效地衡量业务延迟问题是否由 zone reclaim 引起的呢？它引起的延迟究竟有多大呢？这个衡量和观察方法也是我贡献给 Linux Kernel 的：mm/vmscan: add tracepoints for node reclaim ，大致的思路就是利用 linux 的 tracepoint 来做这种量化分析，这是性能开销相对较小的一个方案。

我们可以通过 numactl 来查看服务器的 NUMA 信息，如下是两个 node 的服务器：

	$ numactl --hardware
	available: 2 nodes (0-1)
	node 0 cpus: 0 1 2 3 4 5 6 7 8 9 10 11 24 25 26 27 28 29 30 31 32 33 34 35
	node 0 size: 130950 MB
	node 0 free: 108256 MB
	node 1 cpus: 12 13 14 15 16 17 18 19 20 21 22 23 36 37 38 39 40 41 42 43 44 45 46 47
	node 1 size: 131072 MB
	node 1 free: 122995 MB
	node distances:
	node   0   1 
	  0:  10  21 
	  1:  21  10 

### 如何释放PageCache

	echo 1 > /proc/sys/vm/drop_caches  //释放掉Page Cache中的clean pages (干净页)
	echo 2 > /proc/sys/vm/drop_caches  //释放掉Slab，包括dentry、inode等
	echo 3 > /proc/sys/vm/drop_caches  //既释放Page Cache，又释放Slab
	
	
### 内核机制引起 Page Cache 被回收而产生的业务性能下降


我们在前面已经提到过，在内存紧张的时候会触发内存回收，内存回收会尝试去回收 reclaimable（可以被回收的）内存，这部分内存既包含 Page Cache 又包含 reclaimable kernel memory(比如 slab)。我们可以用下图来简单描述这个过程：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-0a23f14e089cbdee.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

我简单来解释一下这个图。Reclaimer 是指回收者，它可以是内核线程（包括 kswapd）也可以是用户线程。回收的时候，它会依次来扫描 pagecache page 和 slab page 中有哪些可以被回收的，如果有的话就会尝试去回收，如果没有的话就跳过。在扫描可回收 page 的过程中回收者一开始扫描的较少，然后逐渐增加扫描比例直至全部都被扫描完。这就是内存回收的大致过程。

### 如何避免 Page Cache 被回收而引起的性能问题？

* 从应用代码层面来优化；
* 从系统层面来调整。


从应用程序代码层面来解决是相对比较彻底的方案，因为应用更清楚哪些 Page Cache 是重要的，哪些是不重要的，所以就可以明确地来对读写文件过程中产生的 Page Cache 区别对待。比如说，对于重要的数据，可以通过 mlock(2) 来保护它，防止被回收以及被 drop；对于不重要的数据（比如日志），那可以通过 madvise(2) 告诉内核来立即释放这些 Page Cache。


    #include <sys/mman.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #include <string.h>
    #include <fcntl.h>


    #define FILE_NAME "/home/yafang/test/mmap/data"
    #define SIZE (1024*1000*1000)


    int main()
    {
            int fd; 
            char *p; 
            int ret;


            fd = open(FILE_NAME, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
            if (fd < 0)
                    return -1; 


            /* Set size of this file */
            ret = ftruncate(fd, SIZE);
            if (ret < 0)
                    return -1; 


            /* The current offset is 0, so we don't need to reset the offset. */
            /* lseek(fd, 0, SEEK_CUR); */


            /* Mmap virtual memory */
            p = mmap(0, SIZE, PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED, fd, 0); 
            if (!p)
                    return -1; 


            /* Alloc physical memory */
            memset(p, 1, SIZE);


            /* Lock these memory to prevent from being reclaimed */
            mlock(p, SIZE);


            /* Wait until we kill it specifically */
            while (1) {
                    sleep(10);
            }


            /*
            * Unmap the memory.
            * Actually the kernel will unmap it automatically after the
            * process exits, whatever we call munamp() specifically or not.
            */
            munmap(p, SIZE);

            return 0;
    }
    
 
在这个例子中，我们通过 mlock(2) 来锁住了读 FILE_NAME 这个文件内容对应的 Page Cache。在运行上述程序之后，我们来看下该如何来观察这种行为：确认这些 Page Cache 是否被保护住了，被保护了多大。这同样可以通过 /proc/meminfo 来观察:

	
	$ egrep "Unevictable|Mlocked" /proc/meminfo 
	Unevictable:     1000000 kB
	Mlocked:         1000000 kB
 
 然后你可以发现，drop_caches 或者内存回收是回收不了这些内容的，我们的目的也就达到了。
 
 在有些情况下，对应用程序而言，修改源码是件比较麻烦的事，如果可以不修改源码来达到目的那就最好不过了。Linux 内核同样实现了这种不改应用程序的源码而从系统层面调整来保护重要数据的机制，这个机制就是 memory cgroup protection。
 
 它大致的思路是，将需要保护的应用程序使用 memory cgroup 来保护起来，这样该应用程序读写文件过程中所产生的 Page Cache 就会被保护起来不被回收或者最后被回收。memory cgroup protection 大致的原理如下图所示：
 
 ![image.png](https://upload-images.jianshu.io/upload_images/12321605-fbad8f9e482f9da4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

如上图所示，memory cgroup 提供了几个内存水位控制线 memory.{min, low, high, max} 。

* memory.max这是指 memory cgroup 内的进程最多能够分配的内存，如果不设置的话，就默认不做内存大小的限制。
* memory.high如果设置了这一项，当 memory cgroup 内进程的内存使用量超过了该值后就会立即被回收掉，所以这一项的目的是为了尽快的回收掉不活跃的 Page Cache。
* memory.low这一项是用来保护重要数据的，当 memory cgroup 内进程的内存使用量低于了该值后，在内存紧张触发回收后就会先去回收不属于该 memory cgroup 的 Page Cache，等到其他的 Page Cache 都被回收掉后再来回收这些 Page Cache。
* memory.min这一项同样是用来保护重要数据的，只不过与 memoy.low 有所不同的是，当 memory cgroup 内进程的内存使用量低于该值后，即使其他不在该 memory cgroup 内的 Page Cache 都被回收完了也不会去回收这些 Page Cache，可以理解为这是用来保护最高优先级的数据的。

那么，如果你想要保护你的 Page Cache 不被回收，你就可以考虑将你的业务进程放在一个 memory cgroup 中，然后设置 memory.{min,low} 来进行保护；与之相反，如果你想要尽快释放你的 Page Cache，那你可以考虑设置 memory.high 来及时的释放掉不活跃的 Page Cache。


![image.png](https://upload-images.jianshu.io/upload_images/12321605-745ec6aae1887e36.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 内存篇

### 进程的地址空间

![image.png](https://upload-images.jianshu.io/upload_images/12321605-f0d8fa479c9cca7d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

我们用一张表格来简单汇总下这些不同的申请方式所对应的不同内存类型，这张表格也包含了我们在课程上一个模块讲的 Page Cache，所以你可以把它理解为是进程申请内存的类型大汇总：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-5f5bf921f6ec1225.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


### CPU寻址过程


![image.png](https://upload-images.jianshu.io/upload_images/12321605-529d947153c3c37b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

如上图所示，Paging 的大致过程是，CPU 将要请求的虚拟地址传给 MMU（Memory Management Unit，内存管理单元），然后 MMU 先在高速缓存 TLB（Translation Lookaside Buffer，页表缓存）中查找转换关系，如果找到了相应的物理地址则直接访问；如果找不到则在地址转换表（Page Table）里查找计算。最终进程访问的虚拟地址就对应到了实际的物理地址。

### 用数据观察进程的内存

那么都有哪些观察进程的工具呢？我们常用来观察进程内存的工具，比如说 pmap、ps、top 等，都可以很好地来观察进程的内存。

首先我们可以使用 top 来观察系统所有进程的内存使用概况，打开 top 后，然后按 g 再输入 3，从而进入内存模式就可以了。在内存模式中，我们可以看到各个进程内存的 %MEM、VIRT、RES、CODE、DATA、SHR、nMaj、nDRT，这些信息通过 strace 来跟踪 top 进程，你会发现这些信息都是从 /proc/[pid]/statm 和 /proc/[pid]/stat 这个文件里面读取的：

	
	$ strace -p `pidof top`
	open("/proc/16348/statm", O_RDONLY)     = 9
	read(9, "40509 1143 956 24 0 324 0\n", 1024) = 26
	close(9)                                = 0
	...
	open("/proc/16366/stat", O_RDONLY)      = 9
	read(9, "16366 (kworker/u16:1-events_unbo"..., 1024) = 182
	close(9)
	...


![image.png](https://upload-images.jianshu.io/upload_images/12321605-88eacb262111063c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

另外如果你观察仔细的话，可能会发现，有些时候所有进程的 RES 相加起来要比系统总的物理内存大，这是因为 RES 中有一些内存是被一些进程给共享的。


在明白了系统中各个进程的内存使用概况后，如果想要继续看某个进程的内存使用细节，你可以使用 pmap。如下是 pmap 来展示 sshd 进程地址空间里的部分内容：


	$  pmap -x `pidof sshd`
	Address           Kbytes     RSS   Dirty Mode  Mapping 
	000055e798e1d000     768     652       0 r-x-- sshd
	000055e7990dc000      16      16      16 r---- sshd
	000055e7990e0000       4       4       4 rw--- sshd
	000055e7990e1000      40      40      40 rw---   [ anon ]
	...
	00007f189613a000    1800    1624       0 r-x-- libc-2.17.so
	00007f18962fc000    2048       0       0 ----- libc-2.17.so
	00007f18964fc000      16      16      16 r---- libc-2.17.so
	00007f1896500000       8       8       8 rw--- libc-2.17.so
	...
	00007ffd9d30f000     132      40      40 rw---   [ stack ]
	...

每一行表示一种类型的内存（Virtual Memory Area），每一列的含义如下。

* Mapping，用来表示文件映射中占用内存的文件，比如 sshd 这个可执行文件，或者堆[heap]，或者栈[stack]，或者其他，等等。
* Mode，它是该内存的权限，比如，“r-x”是可读可执行，它往往是代码段 (Text Segment)；“rw-”是可读可写，这部分往往是数据段 (Data Segment)；“r–”是只读，这往往是数据段中的只读部分。
* Address、Kbytes、RSS、Dirty，Address 和 Kbytes 分别表示起始地址和虚拟内存的大小，RSS（Resident Set Size）则表示虚拟内存中已经分配的物理内存的大小，Dirty 则表示内存中数据未同步到磁盘的字节数。

可以看到，通过 pmap 我们能够清楚地观察一个进程的整个的地址空间，包括它们分配的物理内存大小，这非常有助于我们对进程的内存使用概况做一个大致的判断。比如说，如果地址空间中[heap]太大，那有可能是堆内存产生了泄漏；再比如说，如果进程地址空间包含太多的 vma（可以把 maps 中的每一行理解为一个 vma），那很可能是应用程序调用了很多 mmap 而没有 munmap；再比如持续观察地址空间的变化，如果发现某些项在持续增长，那很可能是那里存在问题。

pmap 同样也是解析的 /proc 里的文件，具体文件是 /proc/[pid]/maps 和 /proc/[pid]/smaps，其中 smaps 文件相比 maps 的内容更详细，可以理解为是对 maps 的一个扩展。你可以对比 /proc/[pid]/maps 和 pmaps 的输出，你会发现二者的内容是一致的。

   
### Shmem

	$ cat /proc/meminfo
	...
	Shmem  16777216 kB
	...

我们在前面的基础篇里提到，Shmem 是指匿名共享内存，即进程以 mmap（MAP_ANON|MAP_SHARED）这种方式来申请的内存。你可能会有疑问，进程以这种方式来申请的内存不应该是属于进程的 RES（resident）吗？比如下面这个简单的示例：
	
	#include <sys/mman.h>
	#include <string.h>
	#include <unistd.h>
	#define SIZE (1024*1024*1024)
	
	int main()
	{
	        char *p; 
	
	        p = mmap(NULL, SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
	        if (!p)
	                return -1; 
	
	        memset(p, 1, SIZE);
	
	        while (1) {
	                sleep(1);
	        }   
	
	        return 0;
	}
	

先说答案：这跟一种特殊的 Shmem 有关。我们知道，磁盘的速度是远远低于内存的，有些应用程序为了提升性能，会避免将一些无需持续化存储的数据写入到磁盘，而是把这部分临时数据写入到内存中，然后定期或者在不需要这部分数据时，清理掉这部分内容来释放出内存。在这种需求下，就产生了一种特殊的 Shmem：tmpfs。tmpfs 如下图所示：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-aaa95dd95e1b4534.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


它是一种内存文件系统，只存在于内存中，它无需应用程序去申请和释放内存，而是操作系统自动来规划好一部分空间，应用程序只需要往这里面写入数据就可以了，这样会很方便。我们可以使用 moun 命令或者 df 命令来看系统中 tmpfs 的挂载点：

	$ df -h
	Filesystem      Size  Used Avail Use% Mounted on
	...
	tmpfs            16G  15G   1G   94% /run
	...

针对这个问题，解决方案就是限制 systemd 所使用的 tmpfs 的大小，在日志量达到 tmpfs 大小限制时，自动地清理掉临时日志，或者定期清理掉这部分日志，这都可以通过 systemd 的配置文件来做到。tmpfs 的大小可以通过如下命令（比如调整为 2G）调整：


	$ mount -o remount,size=2G /run

tmpfs 作为一种特殊的 Shmem，它消耗的内存是不会体现在进程内存中的，这往往会给问题排查带来一些难度。要想高效地分析这种类型的问题，你必须要去熟悉系统中的内存类型。除了 tmpfs 之外，其他一些类型的内存也不会体现在进程内存中，比如内核消耗的内存：/proc/meminfo 中的 Slab（高速缓存）、KernelStack（内核栈）和 VmallocUsed（内核通过 vmalloc 申请的内存），这些也是你在不清楚内存被谁占用时需要去排查的。

### OOM Kill方式

OOM killer 在杀进程的时候，会把系统中可以被杀掉的进程扫描一遍，根据进程占用的内存以及配置的 oom_score_adj 来计算出进程最终的得分，然后把得分（oom_score）最大的进程给杀掉，如果得分最大的进程有多个，那就把先扫描到的那个给杀掉。

进程的 oom_score 可以通过 /proc/[pid]/oom_score 来查看，你可以扫描一下你系统中所有进程的 oom_score，其中分值最大的那个就是在发生 OOM 时最先被杀掉的进程。不过你需要注意，由于 oom_score 和进程的内存开销有关，而进程的内存开销又是会动态变化的，所以该值也会动态变化。

如果你不想这个进程被首先杀掉，那你可以调整该进程的 oom_score_adj 改变这个 oom_score；如果你的进程无论如何都不能被杀掉，那你可以将 oom_score_adj 配置为 -1000。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-ef7223104caff726.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

### 内核内存

应用程序可以通过 malloc() 和 free() 在用户态申请和释放内存，与之对应，可以通过 kmalloc()/kfree() 以及 vmalloc()/vfree() 在内核态申请和释放内存。当然，还有其他申请和释放内存的方法，但大致可以分为这两类。

从最右侧的物理内存中你可以看出这两类内存申请方式的主要区别，kmalloc() 内存的物理地址是连续的，而 vmalloc() 内存的物理地址则是不连续的。这两种不同类型的内存也是可以通过 /proc/meminfo 来观察的：


	$ cat /proc/meminfo
	...
	Slab:            2400284 kB
	SReclaimable:      47248 kB
	SUnreclaim:      2353036 kB
	...
	VmallocTotal:   34359738367 kB
	VmallocUsed:     1065948 kB
	...

![image.png](https://upload-images.jianshu.io/upload_images/12321605-89fc7bc87f1c17a4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


其中 vmalloc 申请的内存会体现在 VmallocUsed 这一项中，即已使用的 Vmalloc 区大小；而 kmalloc 申请的内存则是体现在 Slab 这一项中，它又分为两部分，其中 SReclaimable 是指在内存紧张的时候可以被回收的内存，而 SUnreclaim 则是不可以被回收只能主动释放的内存。

内核之所以将 kmalloc 和 vmalloc 的信息通过 /proc/meminfo 给导出来，也是为了在它们引起问题的时候，让我们可以有方法来进行排查。在讲述具体的案例以及排查方法之前，我们先以一个简单的程序来看下内核空间是如何进行内存申请和释放的。


	
	/* kmem_test */
	#include <linux/init.h>
	#include <linux/vmalloc.h>
	
	#define SIZE (1024 * 1024 * 1024)
	
	char *kaddr;
	
	char *kmem_alloc(unsigned long size)
	{
	        char *p;
	        p = vmalloc(size);
	        if (!p)
	                pr_info("[kmem_test]: vmalloc failed\n");
	        return p;
	}
	
	void kmem_free(const void *addr)
	{
	        if (addr)
	                vfree(addr);
	}
	
	
	int __init kmem_init(void)
	{
	        pr_info("[kmem_test]: kernel memory init\n");
	        kaddr = kmem_alloc(SIZE);
	        return 0;
	}
	
	
	void __exit kmem_exit(void)
	{
	        kmem_free(kaddr);
	        pr_info("[kmem_test]: kernel memory exit\n");
	}
	
	module_init(kmem_init)
	module_exit(kmem_exit)
	
	MODULE_LICENSE("GPLv2");
	/* kmem_test */
	#include <linux/init.h>
	#include <linux/vmalloc.h>
	
	#define SIZE (1024 * 1024 * 1024)
	
	char *kaddr;
	
	char *kmem_alloc(unsigned long size)
	{
	        char *p;
	        p = vmalloc(size);
	        if (!p)
	                pr_info("[kmem_test]: vmalloc failed\n");
	        return p;
	}
	
	void kmem_free(const void *addr)
	{
	        if (addr)
	                vfree(addr);
	}
	
	
	int __init kmem_init(void)
	{
	        pr_info("[kmem_test]: kernel memory init\n");
	        kaddr = kmem_alloc(SIZE);
	        return 0;
	}
	
	
	void __exit kmem_exit(void)
	{
	        kmem_free(kaddr);
	        pr_info("[kmem_test]: kernel memory exit\n");
	}
	
	module_init(kmem_init)
	module_exit(kmem_exit)
	
	MODULE_LICENSE("GPLv2");
	
	
这是一个典型的内核模块，在这个内核模块中，我们使用 vmalloc 来分配了 1G 的内存空间，然后在模块退出的时候使用 vfree 释放掉它。这在形式上跟应用申请 / 释放内存其实是一致的，只是申请和释放内存的接口函数不一样而已。

我们需要使用 Makefile 来编译这个内核模块：
	
	obj-m = kmem_test.o
	
	all:
	        make -C /lib/modules/`uname -r`/build M=`pwd`
	clean:
	        rm -f *.o *.ko *.mod.c *.mod *.a modules.order Module.symvers
	        
执行 make 命令后就会生成一个 kmem_test 的内核模块，接着执行下面的命令就可以安装该模块了：

	$ insmod kmem_test
	
用 rmmod 命令则可以把它卸载掉：

	$ rmmod kmem_test
	
	
	
![image.png](https://upload-images.jianshu.io/upload_images/12321605-eba928eb16a22401.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## TCP

### TCP 连接的建立过程会受哪些配置项的影响？

![image.png](https://upload-images.jianshu.io/upload_images/12321605-946f31dea498889f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

首先 Client 会给 Server 发送一个 SYN 包，但是该 SYN 包可能会在传输过程中丢失，或者因为其他原因导致 Server 无法处理，此时 Client 这一侧就会触发超时重传机制。但是也不能一直重传下去，重传的次数也是有限制的，这就是 `tcp_syn_retries` 这个配置项来决定的。

假设 `tcp_syn_retries` 为 3，那么 SYN 包重传的策略大致如下：

在 Client 发出 SYN 后，如果过了 1 秒 ，还没有收到 Server 的响应，那么就会进行第一次重传；如果经过 2s 的时间还没有收到 Server 的响应，就会进行第二次重传；一直重传 tcp_syn_retries 次。

对于 `tcp_syn_retries` 为 3 而言，总共会重传 3 次，也就是说从第一次发出 SYN 包后，会一直等待（1 + 2 + 4 + 8）秒，如果还没有收到 Server 的响应，connect() 就会产生 ETIMEOUT 的错误。

tcp_syn_retries 的默认值是 6，也就是说如果 SYN 一直发送失败，会在（1 + 2 + 4 + 8 + 16+ 32 + 64）秒，即 127 秒后产生 ETIMEOUT 的错误。

所以通常情况下，我们都会将数据中心内部服务器的 `tcp_syn_retries` 给调小，这里推荐设置为 2，来减少阻塞的时间。因为对于数据中心而言，它的网络质量是很好的，如果得不到 Server 的响应，很可能是 Server 本身出了问题。在这种情况下，Client 及早地去尝试连接其他的 Server 会是一个比较好的选择，所以对于客户端而言，一般都会做如下调整：

> net.ipv4.tcp_syn_retries = 2

如果 Server 没有响应 Client 的 SYN，除了我们刚才提到的 Server 已经不存在了这种情况外，还有可能是因为 Server 太忙没有来得及响应，或者是 Server 已经积压了太多的半连接（incomplete）而无法及时去处理。

半连接，即收到了 SYN 后还没有回复 SYNACK 的连接，Server 每收到一个新的 SYN 包，都会创建一个半连接，然后把该半连接加入到半连接队列（syn queue）中。syn queue 的长度就是 `tcp_max_syn_backlog` 这个配置项来决定的，当系统中积压的半连接个数超过了该值后，新的 SYN 包就会被丢弃。对于服务器而言，可能瞬间会有非常多的新建连接，所以我们可以适当地调大该值，以免 SYN 包被丢弃而导致 Client 收不到 SYNACK：

> net.ipv4.tcp_max_syn_backlog = 16384

Server 中积压的半连接较多，也有可能是因为有些恶意的 Client 在进行 SYN Flood 攻击。典型的 SYN Flood 攻击如下：Client 高频地向 Server 发 SYN 包，并且这个 SYN 包的源 IP 地址不停地变换，那么 Server 每次接收到一个新的 SYN 后，都会给它分配一个半连接，Server 的 SYNACK 根据之前的 SYN 包找到的是错误的 Client IP， 所以也就无法收到 Client 的 ACK 包，导致无法正确建立 TCP 连接，这就会让 Server 的半连接队列耗尽，无法响应正常的 SYN 包。

在 Server 收到 SYN 包时，不去分配资源来保存 Client 的信息，而是根据这个 SYN 包计算出一个 Cookie 值，然后将 Cookie 记录到 SYNACK 包中发送出去。对于正常的连接，该 Cookies 值会随着 Client 的 ACK 报文被带回来。然后 Server 再根据这个 Cookie 检查这个 ACK 包的合法性，如果合法，才去创建新的 TCP 连接。通过这种处理，SYN Cookies 可以防止部分 SYN Flood 攻击。所以对于 Linux 服务器而言，推荐开启 SYN Cookies：

> net.ipv4.tcp_syncookies = 1

Server 向 Client 发送的 SYNACK 包也可能会被丢弃，或者因为某些原因而收不到 Client 的响应，这个时候 Server 也会重传 SYNACK 包。同样地，重传的次数也是由配置选项来控制的，该配置选项是 tcp_synack_retries。

tcp_synack_retries 的重传策略跟我们在前面讲的 tcp_syn_retries 是一致的，所以我们就不再画图来讲解它了。它在系统中默认是 5，对于数据中心的服务器而言，通常都不需要这么大的值，推荐设置为 2 :

> net.ipv4.tcp_synack_retries = 2


Client 在收到 Serve 的 SYNACK 包后，就会发出 ACK，Server 收到该 ACK 后，三次握手就完成了，即产生了一个 TCP 全连接（complete），它会被添加到全连接队列（accept queue）中。然后 Server 就会调用 accept() 来完成 TCP 连接的建立。

但是，就像半连接队列（syn queue）的长度有限制一样，全连接队列（accept queue）的长度也有限制，目的就是为了防止 Server 不能及时调用 accept() 而浪费太多的系统资源。

全连接队列（accept queue）的长度是由 listen(sockfd, backlog) 这个函数里的 backlog 控制的，而该 backlog 的最大值则是 somaxconn。somaxconn 在 5.4 之前的内核中，默认都是 128（5.4 开始调整为了默认 4096），建议将该值适当调大一些：

> net.core.somaxconn = 16384

当服务器中积压的全连接个数超过该值后，新的全连接就会被丢弃掉。Server 在将新连接丢弃时，有的时候需要发送 reset 来通知 Client，这样 Client 就不会再次重试了。不过，默认行为是直接丢弃不去通知 Client。至于是否需要给 Client 发送 reset，是由 tcp_abort_on_overflow 这个配置项来控制的，该值默认为 0，即不发送 reset 给 Client。推荐也是将该值配置为 0:

> net.ipv4.tcp_abort_on_overflow = 0


这是因为，Server 如果来不及 accept() 而导致全连接队列满，这往往是由瞬间有大量新建连接请求导致的，正常情况下 Server 很快就能恢复，然后 Client 再次重试后就可以建连成功了。也就是说，将 tcp_abort_on_overflow 配置为 0，给了 Client 一个重试的机会。当然，你可以根据你的实际情况来决定是否要使能该选项。


accept() 成功返回后，一个新的 TCP 连接就建立完成了，TCP 连接进入到了 ESTABLISHED 状态：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-6b8043b0ba122772.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


上图就是从 Client 调用 connect()，到 Server 侧 accept() 成功返回这一过程中的 TCP 状态转换。这些状态都可以通过 netstat 或者 ss 命令来看。至此，Client 和 Server 两边就可以正常通信了。

### TCP 连接的断开过程会受哪些配置项的影响？

![image.png](https://upload-images.jianshu.io/upload_images/12321605-473b3f20c05dc25b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

如上所示，当应用程序调用 close() 时，会向对端发送 FIN 包，然后会接收 ACK；对端也会调用 close() 来发送 FIN，然后本端也会向对端回 ACK，这就是 TCP 的四次挥手过程。


首先调用 close() 的一侧是 active close（主动关闭）；而接收到对端的 FIN 包后再调用 close() 来关闭的一侧，称之为 passive close（被动关闭）。在四次挥手的过程中，有三个 TCP 状态需要额外关注，就是上图中深红色的那三个状态：主动关闭方的 `FIN_WAIT_2` 和 `TIME_WAIT`，以及被动关闭方的 `CLOSE_WAIT` 状态。除了 CLOSE_WAIT 状态外，其余两个状态都有对应的系统配置项来控制。

我们首先来看 `FIN_WAIT_2` 状态，TCP 进入到这个状态后，如果本端迟迟收不到对端的 FIN 包，那就会一直处于这个状态，于是就会一直消耗系统资源。Linux 为了防止这种资源的开销，设置了这个状态的超时时间 `tcp_fin_timeout`，默认为 60s，超过这个时间后就会自动销毁该连接。


至于本端为何迟迟收不到对端的 FIN 包，通常情况下都是因为对端机器出了问题，或者是因为太繁忙而不能及时 close()。所以，通常我们都建议将 `tcp_fin_timeout` 调小一些，以尽量避免这种状态下的资源开销。对于数据中心内部的机器而言，将它调整为 2s 足以：

> net.ipv4.tcp_fin_timeout = 2

我们再来看 `TIME_WAIT` 状态，`TIME_WAIT` 状态存在的意义是：最后发送的这个 ACK 包可能会被丢弃掉或者有延迟，这样对端就会再次发送 FIN 包。如果不维持 `TIME_WAIT` 这个状态，那么再次收到对端的 FIN 包后，本端就会回一个 Reset 包，这可能会产生一些异常。

所以维持 `TIME_WAIT` 状态一段时间，可以保障 TCP 连接正常断开。`TIME_WAIT` 的默认存活时间在 Linux 上是 60s（`TCP_TIMEWAIT_LEN`），这个时间对于数据中心而言可能还是有些长了，所以有的时候也会修改内核做些优化来减小该值，或者将该值设置为可通过 sysctl 来调节。

TIME_WAIT 状态存在这么长时间，也是对系统资源的一个浪费，所以系统也有配置项来限制该状态的最大个数，该配置选项就是 `tcp_max_tw_buckets`。对于数据中心而言，网络是相对很稳定的，基本不会存在 FIN 包的异常，所以建议将该值调小一些：

> net.ipv4.tcp_max_tw_buckets = 10000

Client 关闭跟 Server 的连接后，也有可能很快再次跟 Server 之间建立一个新的连接，而由于 TCP 端口最多只有 65536 个，如果不去复用处于 `TIME_WAIT` 状态的连接，就可能在快速重启应用程序时，出现端口被占用而无法创建新连接的情况。所以建议你打开复用 `TIME_WAIT` 的选项：

> net.ipv4.tcp_tw_reuse = 1

还有另外一个选项 `tcp_tw_recycle` 来控制 `TIME_WAIT` 状态，但是该选项是很危险的，因为它可能会引起意料不到的问题，比如可能会引起 NAT 环境下的丢包问题。所以建议将该选项关闭：

> net.ipv4.tcp_tw_recycle = 0

![image.png](https://upload-images.jianshu.io/upload_images/12321605-ba16b5ce1ff45ae1.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

### TCP 数据包的发送过程会受什么影响？

![image.png](https://upload-images.jianshu.io/upload_images/12321605-a8c13789a39c8ebc.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

上图就是一个简略的 TCP 数据包的发送过程。应用程序调用 write(2) 或者 send(2) 系列系统调用开始往外发包时，这些系统调用会把数据包从用户缓冲区拷贝到 TCP 发送缓冲区（TCP Send Buffer），这个 TCP 发送缓冲区的大小是受限制的，这里也是容易引起问题的地方。

TCP 发送缓冲区的大小默认是受 net.ipv4.tcp_wmem 来控制：

	net.ipv4.tcp_wmem = 8192 65536 16777216

tcp_wmem 中这三个数字的含义分别为 min、default、max。TCP 发送缓冲区的大小会在 min 和 max 之间动态调整，初始的大小是 default，这个动态调整的过程是由内核自动来做的，应用程序无法干预。自动调整的目的，是为了在尽可能少的浪费内存的情况下来满足发包的需要。

tcp_wmem 中的 max 不能超过 net.core.wmem_max 这个配置项的值，如果超过了，TCP 发送缓冲区最大就是 net.core.wmem_max。通常情况下，我们需要设置 net.core.wmem_max 的值大于等于 net.ipv4.tcp_wmem 的 max：

	net.core.wmem_max = 16777216


对于 TCP 发送缓冲区的大小，我们需要根据服务器的负载能力来灵活调整。通常情况下我们需要调大它们的默认值，我上面列出的 tcp_wmem 的 min、default、max 这几组数值就是调大后的值，也是我们在生产环境中配置的值。

我之所以将这几个值给调大，是因为我们在生产环境中遇到过 TCP 发送缓冲区太小，导致业务延迟很大的问题，这类问题也是可以使用 systemtap 之类的工具在内核里面打点来进行观察的（观察 sk_stream_wait_memory 这个事件）:


如果你可以观察到 sk_stream_wait_memory 这个事件，就意味着 TCP 发送缓冲区太小了，你需要继续去调大 wmem_max 和 tcp_wmem:max 的值了。

应用程序有的时候会很明确地知道自己发送多大的数据，需要多大的 TCP 发送缓冲区，这个时候就可以通过 setsockopt(2) 里的 SO_SNDBUF 来设置固定的缓冲区大小。一旦进行了这种设置后，tcp_wmem 就会失效，而且这个缓冲区大小设置的是固定值，内核也不会对它进行动态调整。

但是，SO_SNDBUF 设置的最大值不能超过 net.core.wmem_max，如果超过了该值，内核会把它强制设置为 net.core.wmem_max。所以，如果你想要设置 SO_SNDBUF，一定要确认好 net.core.wmem_max 是否满足需求，否则你的设置可能发挥不了作用。通常情况下，我们都不会通过 SO_SNDBUF 来设置 TCP 发送缓冲区的大小，而是使用内核设置的 tcp_wmem，因为如果 SO_SNDBUF 设置得太大就会浪费内存，设置得太小又会引起缓冲区不足的问题。

另外，如果你关注过 Linux 的最新技术动态，你一定听说过 eBPF。你也可以通过 eBPF 来设置 SO_SNDBUF 和 SO_RCVBUF，进而分别设置 TCP 发送缓冲区和 TCP 接收缓冲区的大小。同样地，使用 eBPF 来设置这两个缓冲区时，也不能超过 wmem_max 和 rmem_max。不过 eBPF 在一开始增加设置缓冲区大小的特性时并未考虑过最大值的限制，我在使用的过程中发现这里存在问题，就给社区提交了一个 PATCH 把它给修复了。你感兴趣的话可以看下这个链接：bpf: sock recvbuff must be limited by rmem_max in bpf_setsockopt()。

tcp_wmem 以及 wmem_max 的大小设置都是针对单个 TCP 连接的，这两个值的单位都是 Byte（字节）。系统中可能会存在非常多的 TCP 连接，如果 TCP 连接太多，就可能导致内存耗尽。因此，所有 TCP 连接消耗的总内存也有限制：

	net.ipv4.tcp_mem = 8388608 12582912 16777216

我们通常也会把这个配置项给调大。与前两个选项不同的是，该选项中这些值的单位是 Page（页数），也就是 4K。它也有 3 个值：min、pressure、max。当所有 TCP 连接消耗的内存总和达到 max 后，也会因达到限制而无法再往外发包。

TCP 层处理完数据包后，就继续往下来到了 IP 层。IP 层这里容易触发问题的地方是 net.ipv4.ip_local_port_range 这个配置选项，它是指和其他服务器建立 IP 连接时本地端口（local port）的范围。我们在生产环境中就遇到过默认的端口范围太小，以致于无法创建新连接的问题。所以通常情况下，我们都会扩大默认的端口范围：

	net.ipv4.ip_local_port_range = 1024 65535
	
为了能够对 TCP/IP 数据流进行流控，Linux 内核在 IP 层实现了 qdisc（排队规则）。我们平时用到的 TC 就是基于 qdisc 的流控工具。qdisc 的队列长度是我们用 ifconfig 来看到的 txqueuelen，我们在生产环境中也遇到过因为 txqueuelen 太小导致数据包被丢弃的情况，这类问题可以通过下面这个命令来观察：

	
	
	$ ip -s -s link ls dev eth0
	…
	TX: bytes packets errors dropped carrier collsns
	3263284 25060 0 0 0 0

如果观察到 dropped 这一项不为 0，那就有可能是 txqueuelen 太小导致的。当遇到这种情况时，你就需要增大该值了，比如增加 eth0 这个网络接口的 txqueuelen：

Linux 系统默认的 qdisc 为 pfifo_fast（先进先出），通常情况下我们无需调整它。如果你想使用TCP BBR来改善 TCP 拥塞控制的话，那就需要将它调整为 fq（fair queue, 公平队列）：

	net.core.default_qdisc = fq

经过 IP 层后，数据包再往下就会进入到网卡了，然后通过网卡发送出去。至此，你需要发送出去的数据就走完了 TCP/IP 协议栈，然后正常地发送给对端了。



### TCP 数据包的接收过程会受什么影响？


![image.png](https://upload-images.jianshu.io/upload_images/12321605-7df50d4d2a0995aa.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

从上图可以看出，TCP 数据包的接收流程在整体上与发送流程类似，只是方向是相反的。数据包到达网卡后，就会触发中断（IRQ）来告诉 CPU 读取这个数据包。但是在高性能网络场景下，数据包的数量会非常大，如果每来一个数据包都要产生一个中断，那 CPU 的处理效率就会大打折扣，所以就产生了 NAPI（New API）这种机制让 CPU 一次性地去轮询（poll）多个数据包，以批量处理的方式来提升效率，降低网卡中断带来的性能开销。

那在 poll 的过程中，一次可以 poll 多少个呢？这个 poll 的个数可以通过 sysctl 选项来控制：

	net.core.netdev_budget = 600

该控制选项的默认值是 300，在网络吞吐量较大的场景中，我们可以适当地增大该值，比如增大到 600。增大该值可以一次性地处理更多的数据包。但是这种调整也是有缺陷的，因为这会导致 CPU 在这里 poll 的时间增加，如果系统中运行的任务很多的话，其他任务的调度延迟就会增加。

接下来继续看 TCP 数据包的接收过程。我们刚才提到，数据包到达网卡后会触发 CPU 去 poll 数据包，这些 poll 的数据包紧接着就会到达 IP 层去处理，然后再达到 TCP 层，这时就会面对另外一个很容易引发问题的地方了：TCP Receive Buffer（TCP 接收缓冲区）。

与 TCP 发送缓冲区类似，TCP 接收缓冲区的大小也是受控制的。通常情况下，默认都是使用 tcp_rmem 来控制缓冲区的大小。同样地，我们也会适当地增大这几个值的默认值，来获取更好的网络性能，调整为如下数值：

	net.ipv4.tcp_rmem = 8192 87380 16777216

它也有 3 个字段：min、default、max。TCP 接收缓冲区大小也是在 min 和 max 之间动态调整 ，不过跟发送缓冲区不同的是，这个动态调整是可以通过控制选项来关闭的，这个选项是 tcp_moderate_rcvbuf 。通常我们都是打开它，这也是它的默认值：

	net.ipv4.tcp_moderate_rcvbuf = 1


之所以接收缓冲区有选项可以控制自动调节，而发送缓冲区没有，那是因为 TCP 接收缓冲区会直接影响 TCP 拥塞控制，进而影响到对端的发包，所以使用该控制选项可以更加灵活地控制对端的发包行为。

除了 `tcp_moderate_rcvbuf` 可以控制 TCP 接收缓冲区的动态调节外，也可以通过 setsockopt() 中的配置选项 `SO_RCVBUF` 来控制，这与 TCP 发送缓冲区是类似的。如果应用程序设置了 `SO_RCVBUF` 这个标记，那么 TCP 接收缓冲区的动态调整就是关闭，即使 `tcp_moderate_rcvbuf` 为 1，接收缓冲区的大小始终就为设置的 SO_RCVBUF 这个值。

也就是说，只有在 `tcp_moderate_rcvbuf` 为 1，并且应用程序没有通过 SO_RCVBUF 来配置缓冲区大小的情况下，TCP 接收缓冲区才会动态调节。


同样地，与 TCP 发送缓冲区类似，SO_RCVBUF 设置的值最大也不能超过 `net.core.rmem_max`。通常情况下，我们也需要设置 `net.core.rmem_max` 的值大于等于 `net.ipv4.tcp_rmem` 的 max：

	net.core.rmem_max = 16777216

我们在生产环境中也遇到过，因达到了 TCP 接收缓冲区的限制而引发的丢包问题。但是这类问题不是那么好追踪的，没有一种很直观地追踪这种行为的方式，所以我便在我们的内核里添加了针对这种行为的统计。


## CPU

### CPU 是如何选择线程执行的 ？

你知道，一个系统中可能会运行着非常多的线程，这些线程数可能远超系统中的 CPU 核数，这时候这些任务就需要排队，每个 CPU 都会维护着自己运行队列（runqueue）里的线程。这个运行队列的结构大致如下图所示：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-e85459e43642ee35.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

每个 CPU 都有自己的运行队列（runqueue），需要运行的线程会被加入到这个队列中。因为有些线程的优先级高，Linux 内核为了保障这些高优先级任务的执行，设置了不同的调度类（Scheduling Class），如下所示：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-b44577ea158f2dbb.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

这几个调度类的优先级如下：Deadline > Realtime > Fair。Linux 内核在选择下一个任务执行时，会按照该顺序来进行选择，也就是先从 dl_rq 里选择任务，然后从 rt_rq 里选择任务，最后从 cfs_rq 里选择任务。所以实时任务总是会比普通任务先得到执行。

如果你的某些任务对延迟容忍度很低，比如说在嵌入式系统中就有很多这类任务，那就可以考虑将你的任务设置为实时任务，比如将它设置为 SCHED_FIFO 的任务：

	$ chrt -f -p 1 1327

如果你不做任何设置的话，用户线程在默认情况下都是普通线程，也就是属于 Fair 调度类，由 CFS 调度器来进行管理。CFS 调度器的目的是为了实现线程运行的公平性，举个例子，假设一个 CPU 上有两个线程需要执行，那么每个线程都将分配 50% 的 CPU 时间，以保障公平性。其实，各个线程之间执行时间的比例，也是可以人为干预的，比如在 Linux 上可以调整进程的 nice 值来干预，从而让优先级高一些的线程执行更多时间。这就是 CFS 调度器的大致思想。


### TOP 指标


![image.png](https://upload-images.jianshu.io/upload_images/12321605-fa2896f09bbc4b2e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

在上面这几项中，idle 和 wait 是 CPU 不工作的时间，其余的项都是 CPU 工作的时间。idle 和 wait 的主要区别是，idle 是 CPU 无事可做，而 wait 则是 CPU 想做事却做不了。你也可以将 wait 理解为是一类特殊的 idle，即该 CPU 上有至少一个线程阻塞在 I/O 时的 idle。

而我们通过对 CPU 利用率的细化监控发现，案例中的 CPU 利用率飙高是由 sys 利用率变高导致的，也就是说 sys 利用率会忽然飙高一下，比如在 usr 低于 30% 的情况下，sys 会高于 15%，持续几秒后又恢复正常。


从该调用栈我们可以看出，此时这个 java 线程在申请 THP（do_huge_pmd_anonymous_page）。THP 就是透明大页，它是一个 2M 的连续物理内存。但是，因为这个时候物理内存中已经没有连续 2M 的内存空间了，所以触发了 direct compaction（直接内存规整），内存规整的过程可以用下图来表示：


![image.png](https://upload-images.jianshu.io/upload_images/12321605-6a9735b7f83c1a08.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)




这个过程并不复杂，在进行 compcation 时，线程会从前往后扫描已使用的 movable page，然后从后往前扫描 free page，扫描结束后会把这些 movable page 给迁移到 free page 里，最终规整出一个 2M 的连续物理内存，这样 THP 就可以成功申请内存了。


direct compaction 这个过程是很耗时的，而且在 2.6.32 版本的内核上，该过程需要持有粗粒度的锁，所以在运行过程中线程还可能会主动检查（_cond_resched）是否有其他更高优先级的任务需要执行。如果有的话就会让其他线程先执行，这便进一步加剧了它的执行耗时。这也就是 sys 利用率飙高的原因。关于这些，你也都可以从内核源码的注释来看到：

关闭了生产环境上的 THP 后，我们又在线下测试环境中评估了 THP 对该业务的性能影响，我们发现 THP 并不能给该业务带来明显的性能提升，即使是在内存不紧张、不会触发内存规整的情况下。这也引起了我的思考，**THP 究竟适合什么样的业务呢**？

这就要从 THP 的目的来说起了。我们长话短说，THP 的目的是用一个页表项来映射更大的内存（大页），这样可以减少 Page Fault，因为需要的页数少了。当然，这也会提升 TLB 命中率，因为需要的页表项也少了。如果进程要访问的数据都在这个大页中，那么这个大页就会很热，会被缓存在 Cache 中。而大页对应的页表项也会出现在 TLB 中，从上一讲的存储层次我们可以知道，这有助于性能提升。但是反过来，假设应用程序的数据局部性比较差，它在短时间内要访问的数据很随机地位于不同的大页上，那么大页的优势就会消失。

因此，我们基于大页给业务做性能优化的时候，首先要评估业务的数据局部性，尽量把业务的热点数据聚合在一起，以便于充分享受大页的优势。以我在华为任职期间所做的大页性能优化为例，我们将业务的热点数据聚合在一起，然后将这些热点数据分配到大页上，再与不使用大页的情况相比，最终发现这可以带来 20% 以上的性能提升。对于 TLB 较小的架构（比如 MIPS 这种架构），它可以带来 50% 以上的性能提升。当然了，我们在这个过程中也对内核的大页代码做了很多优化，这里就不展开说了。

针对 THP 的使用，我在这里给你几点建议：

* 不要将 /sys/kernel/mm/transparent_hugepage/enabled 配置为 always，你可以将它配置为 madvise。如果你不清楚该如何来配置，那就将它配置为 never；
* 如果你想要用 THP 优化业务，最好可以让业务以 madvise 的方式来使用大页，即通过修改业务代码来指定特定数据使用 THP，因为业务更熟悉自己的数据流；
* 很多时候修改业务代码会很麻烦，如果你不想修改业务代码的话，那就去优化 THP 的内核代码吧。


### strace 原理

![image.png](https://upload-images.jianshu.io/upload_images/12321605-691f7f14e99c1dd6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

我们从图中可以看到，对于正在运行的进程而言，strace 可以 attach 到目标进程上，这是通过 ptrace 这个系统调用实现的（gdb 工具也是如此）。ptrace 的 PTRACE_SYSCALL 会去追踪目标进程的系统调用；目标进程被追踪后，每次进入 syscall，都会产生 SIGTRAP 信号并暂停执行；追踪者通过目标进程触发的 SIGTRAP 信号，就可以知道目标进程进入了系统调用，然后追踪者会去处理该系统调用，我们用 strace 命令观察到的信息输出就是该处理的结果；追踪者处理完该系统调用后，就会恢复目标进程的执行。被恢复的目标进程会一直执行下去，直到下一个系统调用。

你可以发现，目标进程每执行一次系统调用都会被打断，等 strace 处理完后，目标进程才能继续执行，这就会给目标进程带来比较明显的延迟。因此，在生产环境中我不建议使用该命令，如果你要使用该命令来追踪生产环境的问题，那就一定要做好预案。

假设我们使用 strace 跟踪到，线程延迟抖动是由某一个系统调用耗时长导致的，那么接下来我们该怎么继续追踪呢？这就到了应用开发者和运维人员需要拓展分析边界的时刻了，对内核开发者来说，这才算是分析问题的开始。



