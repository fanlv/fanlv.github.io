- [binlog && redo log](#binlog--redo-log)
	- [什么是 binlog](#什么是-binlog)
	- [什么是 redo log](#什么是-redo-log)
	- [binlog 和 redo log 不同点](#binlog-和-redo-log-不同点)
	- [binlog 的写入机制](#binlog-的写入机制)
	- [redo log 的写入机制](#redo-log-的写入机制)
	- [redo log 存储方式](#redo-log-存储方式)
	- [组提交（group commit）机制](#组提交group-commit机制)
		- [binlog 的三种格式](#binlog-的三种格式)
		- [为什么会有 mixed 格式的 binlog？](#为什么会有-mixed-格式的-binlog)
		- [为什么不用mix格式日志？](#为什么不用mix格式日志)
	- [Xid](#xid)
	- [其他问题](#其他问题)
		- [MySQL 怎么知道 binlog 是完整的?](#mysql-怎么知道-binlog-是完整的)
		- [redo log 和 binlog 是怎么关联起来的?](#redo-log-和-binlog-是怎么关联起来的)
		- [处于 prepare 阶段的 redo log 加上完整 binlog，重启就能恢复，MySQL 为什么要这么设计?](#处于-prepare-阶段的-redo-log-加上完整-binlog重启就能恢复mysql-为什么要这么设计)
		- [正常运行中的实例，数据写入后的最终落盘，是从 redo log 更新过来的还是从 buffer pool 更新过来的呢？](#正常运行中的实例数据写入后的最终落盘是从-redo-log-更新过来的还是从-buffer-pool-更新过来的呢)
		- [redo log buffer 是什么？是先修改内存，还是先写 redo log 文件？](#redo-log-buffer-是什么是先修改内存还是先写-redo-log-文件)
		- [WAL 机制是减少磁盘写，可是每次提交事务都要写 redo log 和 binlog，这磁盘读写次数也没变少呀？](#wal-机制是减少磁盘写可是每次提交事务都要写-redo-log-和-binlog这磁盘读写次数也没变少呀)
		- [如果你的 MySQL 现在出现了性能瓶颈，而且瓶颈在 IO 上，可以通过哪些方法来提升性能呢？](#如果你的-mysql-现在出现了性能瓶颈而且瓶颈在-io-上可以通过哪些方法来提升性能呢)
		- [执行一个 update 语句以后，我再去执行 hexdump 命令直接查看 ibd 文件内容，为什么没有看到数据有改变呢？](#执行一个-update-语句以后我再去执行-hexdump-命令直接查看-ibd-文件内容为什么没有看到数据有改变呢)
		- [为什么 binlog cache 是每个线程自己维护的，而 redo log buffer 是全局共用的？](#为什么-binlog-cache-是每个线程自己维护的而-redo-log-buffer-是全局共用的)
		- [事务执行期间，还没到提交阶段，如果发生 crash 的话，redo log 肯定丢了，这会不会导致主备不一致呢？](#事务执行期间还没到提交阶段如果发生-crash-的话redo-log-肯定丢了这会不会导致主备不一致呢)
		- [如果 binlog 写完盘以后发生 crash，这时候还没给客户端答复就重启了。等客户端再重连进来，发现事务已经提交成功了，这是不是 bug？](#如果-binlog-写完盘以后发生-crash这时候还没给客户端答复就重启了等客户端再重连进来发现事务已经提交成功了这是不是-bug)
		- [为什么binlog 是不能“被打断的”的呢？主要出于什么考虑？](#为什么binlog-是不能被打断的的呢主要出于什么考虑)
		- [主从循环复制问题](#主从循环复制问题)
		- [WAL(write-ahead-log)日志与回滚（rollback）日志的区别](#walwrite-ahead-log日志与回滚rollback日志的区别)
- [SQL执行过程](#sql执行过程)
	- [一条SQL如何执行？](#一条sql如何执行)
	- [一个SQL 更新过程](#一个sql-更新过程)
		- [change buffer](#change-buffer)
		- [change buffer 的使用场景](#change-buffer-的使用场景)
	- [一个 SQL 查询过程](#一个-sql-查询过程)
		- [缓冲池(buffer pool)](#缓冲池buffer-pool)
		- [索引下推](#索引下推)
	- [Mysql优化器](#mysql优化器)
		- [索引选择异常和处理](#索引选择异常和处理)
		- [字符串索引存储](#字符串索引存储)
		- [最左前缀原则](#最左前缀原则)
	- [脏页](#脏页)
		- [强制刷脏页的场景](#强制刷脏页的场景)
		- [刷脏页速度](#刷脏页速度)
	- [其他问题](#其他问题-1)
		- [覆盖索引](#覆盖索引)
		- [当 MySQL 去更新一行，但是要修改的值跟原来的值是相同的，这时候 MySQL 会真的去执行一次修改吗？](#当-mysql-去更新一行但是要修改的值跟原来的值是相同的这时候-mysql-会真的去执行一次修改吗)
		- [我查这么多数据，会不会把数据库内存打爆](#我查这么多数据会不会把数据库内存打爆)
		- [读写分离 - 过期读问题](#读写分离---过期读问题)
	- [事务](#事务)
	- [当前读 ，快照读](#当前读-快照读)
		- [事务隔离](#事务隔离)
- [锁](#锁)
	- [加锁原则](#加锁原则)
	- [锁粒度](#锁粒度)
		- [全局锁](#全局锁)
			- [备份](#备份)
		- [表级别锁](#表级别锁)
	- [两阶段锁](#两阶段锁)
	- [死锁和死锁检测](#死锁和死锁检测)
		- [select 和 insert死锁场景](#select-和-insert死锁场景)
	- [热点行问题](#热点行问题)

## binlog && redo log

### 什么是 binlog

* binlog 是逻辑日志，记录的是这个语句的原始逻辑/变化，比如“`给 ID=2 这一行的 c 字段加 1 `”。 
* binlog 是追加写，不会覆盖之前的数据，可以提供完整的数据归档的能力。

### 什么是 redo log

* redo log 是物理日志，记录的是“在某个数据页上做了什么修改”；
* redo log 提供 crash-safe 能力。
* 一般只有4G ，4个文件，循环复写。


### binlog 和 redo log 不同点

因为最开始 MySQL 里并没有 InnoDB 引擎。MySQL 自带的引擎是 MyISAM，但是 MyISAM 没有 crash-safe 的能力，binlog 日志只能用于归档。而 InnoDB 是另一个公司以插件形式引入 MySQL 的，既然只依靠 binlog 是没有 crash-safe 能力的，所以 InnoDB 使用另外一套日志系统——也就是 redo log 来实现 crash-safe 能力。


1. redo log 是 InnoDB 引擎特有的；binlog 是 MySQL 的 Server 层实现的，所有引擎都可以使用。
2. redo log 是物理日志，记录的是“在某个数据页上做了什么修改”；binlog 是逻辑日志，记录的是这个语句的原始逻辑，比如“给 ID=2 这一行的 c 字段加 1 ”。
3. redo log 是循环写的，空间固定会用完；binlog 是可以追加写入的。“追加写”是指 binlog 文件写到一定大小后会切换到下一个，并不会覆盖以前的日志。



### binlog 的写入机制

其实，binlog 的写入逻辑比较简单：事务执行过程中，先把日志写到 binlog cache，事务提交的时候，再把 binlog cache 写到 binlog 文件中。


一个事务的 binlog 是不能被拆开的，因此不论这个事务多大，也要确保一次性写入。这就涉及到了 binlog cache 的保存问题。

系统给 binlog cache 分配了一片内存，每个线程一个，参数 binlog_cache_size 用于控制单个线程内 binlog cache 所占内存的大小。如果超过了这个参数规定的大小，就要暂存到磁盘。

事务提交的时候，执行器把 binlog cache 里的完整事务写入到 binlog 中，并清空 binlog cache。状态如图 1 所示。


![image.png](https://upload-images.jianshu.io/upload_images/12321605-d9e2d6cb67016131.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

可以看到，每个线程有自己 binlog cache，但是共用同一份 binlog 文件。

* 图中的 write，指的就是指把日志写入到文件系统的 page cache，并没有把数据持久化到磁盘，所以速度比较快。
* 图中的 fsync，才是将数据持久化到磁盘的操作。一般情况下，我们认为 fsync 才占磁盘的 IOPS。

write 和 fsync 的时机，是由参数 sync_binlog 控制的：

* sync_binlog=0 的时候，表示每次提交事务都只 write，不 fsync；
* sync_binlog=1 的时候，表示每次提交事务都会执行 fsync；
* sync_binlog=N(N>1) 的时候，表示每次提交事务都 write，但累积 N 个事务后才 fsync。


因此，在出现 IO 瓶颈的场景里，将 sync_binlog 设置成一个比较大的值，可以提升性能。在实际的业务场景中，考虑到丢失日志量的可控性，一般不建议将这个参数设成 0，比较常见的是将其设置为 100~1000 中的某个数值。

但是，将 sync_binlog 设置为 N，对应的风险是：如果主机发生异常重启，会丢失最近 N 个事务的 binlog 日志。


### redo log 的写入机制

事务在执行过程中，生成的 redo log 是要先写到 redo log buffer 的。

redo log buffer 里面的内容，是不是每次生成后都要直接持久化到磁盘呢？答案是，不需要。

如果事务执行期间 MySQL 发生异常重启，那这部分日志就丢了。由于事务并没有提交，所以这时日志丢了也不会有损失。

那么，另外一个问题是，事务还没提交的时候，redo log buffer 中的部分日志有没有可能被持久化到磁盘呢？答案是，确实会有。

这个问题，要从 redo log 可能存在的三种状态说起。这三种状态，对应的就是图 2 中的三个颜色块。

![redo log 三种状态](https://upload-images.jianshu.io/upload_images/12321605-15e11ef8355650a2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

1. 存在 redo log buffer 中，物理上是在 MySQL 进程内存中，就是图中的红色部分；
2. 写到磁盘 (write)，但是没有持久化（fsync)，物理上是在文件系统的 page cache 里面，也就是图中的黄色部分；
3. 持久化到磁盘，对应的是 hard disk，也就是图中的绿色部分。

日志写到 redo log buffer 是很快的，wirte 到 page cache 也差不多，但是持久化到磁盘的速度就慢多了。

为了控制 redo log 的写入策略，InnoDB 提供了 innodb_flush_log_at_trx_commit 参数，它有三种可能取值：

* 设置为 0 的时候，表示每次事务提交时都只是把 redo log 留在 redo log buffer 中 ;
* 设置为 1 的时候，表示每次事务提交时都将 redo log 直接持久化到磁盘；
* 设置为 2 的时候，表示每次事务提交时都只是把 redo log 写到 page cache。

InnoDB 有一个后台线程，每隔 1 秒，就会把 redo log buffer 中的日志，调用 write 写到文件系统的 page cache，然后调用 fsync 持久化到磁盘。

注意，事务执行中间过程的 redo log 也是直接写在 redo log buffer 中的，这些 redo log 也会被后台线程一起持久化到磁盘。也就是说，一个没有提交的事务的 redo log，也是可能已经持久化到磁盘的。

实际上，除了后台线程每秒一次的轮询操作外，还有两种场景会让一个没有提交的事务的 redo log 写入到磁盘中。

1. 一种是，redo log buffer 占用的空间即将达到 innodb_log_buffer_size 一半的时候，后台线程会主动写盘。注意，由于这个事务并没有提交，所以这个写盘动作只是 write，而没有调用 fsync，也就是只留在了文件系统的 page cache。
2. 另一种是，并行的事务提交的时候，顺带将这个事务的 redo log buffer 持久化到磁盘。假设一个事务 A 执行到一半，已经写了一些 redo log 到 buffer 中，这时候有另外一个线程的事务 B 提交，如果 innodb_flush_log_at_trx_commit 设置的是 1，那么按照这个参数的逻辑，事务 B 要把 redo log buffer 里的日志全部持久化到磁盘。这时候，就会带上事务 A 在 redo log buffer 里的日志一起持久化到磁盘。

这里需要说明的是，我们介绍两阶段提交的时候说过，时序上 redo log 先 prepare， 再写 binlog，最后再把 redo log commit。

如果把 innodb_flush_log_at_trx_commit 设置成 1，那么 redo log 在 prepare 阶段就要持久化一次，因为有一个崩溃恢复逻辑是要依赖于 prepare 的 redo log，再加上 binlog 来恢复的。（如果你印象有点儿模糊了，可以再回顾下第 15 篇文章中的相关内容）。

每秒一次后台轮询刷盘，再加上崩溃恢复这个逻辑，InnoDB 就认为 redo log 在 commit 的时候就不需要 fsync 了，只会 write 到文件系统的 page cache 中就够了。


通常我们说 MySQL 的“双 1”配置，指的就是 sync_binlog 和 innodb_flush_log_at_trx_commit 都设置成 1。也就是说，一个事务完整提交前，需要等待两次刷盘，一次是 redo log（prepare 阶段），一次是 binlog。




### redo log 存储方式

当有一条记录需要更新的时候，InnoDB 引擎就会先把记录写到 redo log 里面，并更新内存，这个时候更新就算完成了。同时，InnoDB 引擎会在适当的时候，将这个操作记录更新到磁盘里面，而这个更新往往是在系统比较空闲的时候做。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-3dded44ffd4d9c82.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

write pos 是当前记录的位置，一边写一边后移，写到第 3 号文件末尾后就回到 0 号文件开头。checkpoint 是当前要擦除的位置，也是往后推移并且循环的，擦除记录前要把记录更新到数据文件。

write pos 和 checkpoint **之间的是还空着的部分，可以用来记录新的操作**。如果 write pos 追上 checkpoint，**表示“粉板”满了，这时候不能再执行新的更新**，得停下来先擦掉一些记录，把 checkpoint 推进一下。

有了 redo log，InnoDB 就可以保证即使数据库发生异常重启，之前提交的记录都不会丢失，这个能力称为 **crash-safe**。

redo log 用于保证 crash-safe 能力。`innodb_flush_log_at_trx_commit` 这个参数设置成 1 的时候，表示每次事务的 redo log 都直接持久化到磁盘。这个参数我建议你设置成 1，这样可以保证 MySQL 异常重启之后数据不丢失。


### 组提交（group commit）机制

日志逻辑序列号（log sequence number，LSN）。LSN 是单调递增的，用来对应 redo log 的一个个写入点。每次写入长度为 length 的 redo log， LSN 的值就会加上 length。

LSN 也会写到 InnoDB 的数据页中，来确保数据页不会被多次执行重复的 redo log。关于 LSN 和 redo log、checkpoint 的关系，我会在后面的文章中详细展开。

如图 3 所示，是三个并发事务 (trx1, trx2, trx3) 在 prepare 阶段，都写完 redo log buffer，持久化到磁盘的过程，对应的 LSN 分别是 50、120 和 160。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-126180d07c62c833.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


MySQL 为了让组提交的效果更好，把 redo log 做 fsync 的时间拖到了步骤 1 之后。也就是说，上面的图变成了这样：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-bc7bede59859cd59.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

这么一来，binlog 也可以组提交了。在执行图 5 中第 4 步把 binlog fsync 到磁盘时，如果有多个事务的 binlog 已经写完了，也是一起持久化的，这样也可以减少 IOPS 的消耗。

不过通常情况下第 3 步执行得会很快，所以 binlog 的 write 和 fsync 间的间隔时间短，导致能集合到一起持久化的 binlog 比较少，因此 binlog 的组提交的效果通常不如 redo log 的效果那么好。

如果你想提升 binlog 组提交的效果，可以通过设置 `binlog_group_commit_sync_delay` 和 `binlog_group_commit_sync_no_delay_count` 来实现。

1. `binlog_group_commit_sync_delay` 参数，表示延迟多少微秒后才调用 fsync;
2. `binlog_group_commit_sync_no_delay_count` 参数，表示累积多少次以后才调用 fsync。


#### binlog 的三种格式

binlog 的三种格式 ：statement、row、mixed


	mysql> CREATE TABLE `t` (
	  `id` int(11) NOT NULL,
	  `a` int(11) DEFAULT NULL,
	  `t_modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	  PRIMARY KEY (`id`),
	  KEY `a` (`a`),
	  KEY `t_modified`(`t_modified`)
	) ENGINE=InnoDB;
	
	insert into t values(1,1,'2018-11-13');
	insert into t values(2,2,'2018-11-12');
	insert into t values(3,3,'2018-11-11');
	insert into t values(4,4,'2018-11-10');
	insert into t values(5,5,'2018-11-09');
	
注意，下面这个语句包含注释，如果你用 MySQL 客户端来做这个实验的话，要记得加 -c 参数，否则客户端会自动去掉注释。

	mysql> delete from t /*comment*/  where a>=4 and t_modified<='2018-11-10' limit 1;

当 binlog_format=statement 时，binlog 里面记录的就是 SQL 语句的原文。你可以用

	mysql> show binlog events in 'master.000001';
	
命令看 binlog 中的内容。

![图 4 delete 执行 warnings](https://upload-images.jianshu.io/upload_images/12321605-209fd6c3cdf883d9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


* 第二行是一个 BEGIN，跟第四行的 commit 对应，表示中间是一个事务；
* 第三行就是真实执行的语句了。可以看到，在真实执行的 delete 命令之前，还有一个“use ‘test’”命令。这条命令不是我们主动执行的，而是 MySQL 根据当前要操作的表所在的数据库，自行添加的。这样做可以保证日志传到备库去执行的时候，不论当前的工作线程在哪个库里，都能够正确地更新到 test 库的表 t。
* use 'test’命令之后的 delete 语句，就是我们输入的 SQL 原文了。可以看到，binlog“忠实”地记录了 SQL 命令，甚至连注释也一并记录了。
* 最后一行是一个 COMMIT。你可以看到里面写着 xid=61。你还记得这个 XID 是做什么用的吗？如果记忆模糊了，可以再回顾一下第 15 篇文章中的相关内容。

为了说明 statement 和 row 格式的区别，我们来看一下这条 delete 命令的执行效果图：

![图 4 delete 执行 warnings](https://upload-images.jianshu.io/upload_images/12321605-0b2d0b2aaa4c9ba9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


可以看到，运行这条 delete 命令产生了一个 warning，原因是当前 binlog 设置的是 statement 格式，并且语句中有 limit，所以这个命令可能是 unsafe 的。

为什么这么说呢？这是因为 delete 带 limit，很可能会出现主备数据不一致的情况。比如上面这个例子：

1. 如果 delete 语句使用的是索引 a，那么会根据索引 a 找到第一个满足条件的行，也就是说删除的是 a=4 这一行；
2. 但如果使用的是索引 `t_modified`，那么删除的就是 `t_modified='2018-11-09’`也就是 a=5 这一行。

由于 statement 格式下，记录到 binlog 里的是语句原文，因此可能会出现这样一种情况：在主库执行这条 SQL 语句的时候，用的是索引 a；而在备库执行这条 SQL 语句的时候，却使用了索引 t_modified。因此，MySQL 认为这样写是有风险的。

那么，如果我把 binlog 的格式改为 binlog_format=‘row’， 是不是就没有这个问题了呢？我们先来看看这时候 binog 中的内容吧。


![图 5 row 格式 binlog 示例](https://upload-images.jianshu.io/upload_images/12321605-9339bcfa75858829.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

可以看到，与 statement 格式的 binlog 相比，前后的 BEGIN 和 COMMIT 是一样的。但是，row 格式的 binlog 里没有了 SQL 语句的原文，而是替换成了两个 event：Table_map 和 Delete_rows。

* `Table_map` event，用于说明接下来要操作的表是 test 库的表 t;
* `Delete_rows` event，用于定义删除的行为。

其实，我们通过图 5 是看不到详细信息的，还需要借助 mysqlbinlog 工具，用下面这个命令解析和查看 binlog 中的内容。因为图 5 中的信息显示，这个事务的 binlog 是从 8900 这个位置开始的，所以可以用 start-position 参数来指定从这个位置的日志开始解析。


	mysqlbinlog  -vv data/master.000001 --start-position=8900;
	
	
![图 6 row 格式 binlog 示例的详细信息](https://upload-images.jianshu.io/upload_images/12321605-945744ba90208f3c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

从这个图中，我们可以看到以下几个信息：

* server id 1，表示这个事务是在 server_id=1 的这个库上执行的。
* 每个 event 都有 CRC32 的值，这是因为我把参数 binlog_checksum 设置成了 CRC32。
* Table_map event 跟在图 5 中看到的相同，显示了接下来要打开的表，map 到数字 226。现在我们这条 SQL 语句只操作了一张表，如果要操作多张表呢？每个表都有一个对应的 Table_map event、都会 map 到一个单独的数字，用于区分对不同表的操作。
* 我们在 mysqlbinlog 的命令中，使用了 -vv 参数是为了把内容都解析出来，所以从结果里面可以看到各个字段的值（比如，@1=4、 @2=4 这些值）。
* binlog_row_image 的默认配置是 FULL，因此 Delete_event 里面，包含了删掉的行的所有字段的值。如果把 binlog_row_image 设置为 MINIMAL，则只会记录必要的信息，在这个例子里，就是只会记录 id=4 这个信息。
* 最后的 Xid event，用于表示事务被正确地提交了。


#### 为什么会有 mixed 格式的 binlog？

* 因为有些 statement 格式的 binlog 可能会导致主备不一致，所以要使用 row 格式。
* 但 row 格式的缺点是，很占空间。比如你用一个 delete 语句删掉 10 万行数据，用 statement 的话就是一个 SQL 语句被记录到 binlog 中，占用几十个字节的空间。但如果用 row 格式的 binlog，就要把这 10 万条记录都写到 binlog 中。这样做，不仅会占用更大的空间，同时写 binlog 也要耗费 IO 资源，影响执行速度。
* 所以，MySQL 就取了个折中方案，也就是有了 mixed 格式的 binlog。mixed 格式的意思是，MySQL 自己会判断这条 SQL 语句是否可能引起主备不一致，如果有可能，就用 row 格式，否则就用 statement 格式。

也就是说，mixed 格式可以利用 statment 格式的优点，同时又避免了数据不一致的风险。

因此，如果你的线上 MySQL 设置的 binlog 格式是 statement 的话，那基本上就可以认为这是一个不合理的设置。你至少应该把 binlog 的格式设置为 mixed。

#### 为什么不用mix格式日志？

现在越来越多的场景要求把 MySQL 的 binlog 格式设置成 row。这么做的理由有很多，一个可以直接看出来的好处：**恢复数据**。

接下来，我们就分别从 delete、insert 和 update 这三种 SQL 语句的角度，来看看数据恢复的问题。

* 即使我执行的是 delete 语句，row 格式的 binlog 也会把被删掉的行的整行信息保存起来。所以，如果你在执行完一条 delete 语句以后，发现删错数据了，可以直接把 binlog 中记录的 delete 语句转成 insert，把被错删的数据插入回去就可以恢复了。
* 如果你是执行错了 insert 语句呢？那就更直接了。row 格式下，insert 语句的 binlog 里会记录所有的字段信息，这些信息可以用来精确定位刚刚被插入的那一行。这时，你直接把 insert 语句转成 delete 语句，删除掉这被误插入的一行数据就可以了。
* 如果执行的是 update 语句的话，binlog 里面会记录修改前整行的数据和修改后的整行数据。所以，如果你误执行了 update 语句的话，只需要把这个 event 前后的两行信息对调一下，再去数据库里面执行，就能恢复这个更新操作了。

其实，由 delete、insert 或者 update 语句导致的数据操作错误，需要恢复到操作之前状态的情况，也时有发生。MariaDB 的Flashback工具就是基于上面介绍的原理来回滚数据的。

### Xid

redo log 和 binlog有一个共同的字段叫作 Xid。它在 MySQL 中是用来对应事务的。

MySQL 内部维护了一个全局变量 global_query_id，每次执行语句的时候将它赋值给 Query_id，然后给这个变量加 1。如果当前语句是这个事务执行的第一条语句，那么 MySQL 还会同时把 Query_id 赋值给这个事务的 Xid。

而 global_query_id 是一个纯内存变量，重启之后就清零了。所以你就知道了，在同一个数据库实例中，不同事务的 Xid 也是有可能相同的。

但是 MySQL 重启之后会重新生成新的 binlog 文件，这就保证了，同一个 binlog 文件里，Xid 一定是惟一的。

虽然 MySQL 重启不会导致同一个 binlog 里面出现两个相同的 Xid，但是如果 global_query_id 达到上限后，就会继续从 0 开始计数。从理论上讲，还是就会出现同一个 binlog 里面出现相同 Xid 的场景。

因为 global_query_id 定义的长度是 8 个字节，这个自增值的上限是 264-1。要出现这种情况，必须是下面这样的过程：

1. 执行一个事务，假设 Xid 是 A；
2. 接下来执行2的64次方查询语句，让 global_query_id 回到 A；
3. 再启动一个事务，这个事务的 Xid 也是 A。

不过，2的64次方这个值太大了，大到你可以认为这个可能性只会存在于理论上。


### 其他问题

#### MySQL 怎么知道 binlog 是完整的?

* statement 格式的 binlog，最后会有 COMMIT；
* row 格式的 binlog，最后会有一个 XID event。


#### redo log 和 binlog 是怎么关联起来的?
它们有一个共同的数据字段，叫 XID。崩溃恢复的时候，会按顺序扫描 redo log：

* 如果碰到既有 prepare、又有 commit 的 redo log，就直接提交；
* 如果碰到只有 parepare、而没有 commit 的 redo log，就拿着 XID 去 binlog 找对应的事务。



#### 处于 prepare 阶段的 redo log 加上完整 binlog，重启就能恢复，MySQL 为什么要这么设计?

这个问题还是跟我们在反证法中说到的数据与备份的一致性有关。在时刻 B，也就是 binlog 写完以后 MySQL 发生崩溃，这时候 binlog 已经写入了，之后就会被从库（或者用这个 binlog 恢复出来的库）使用。

**那能不能只用 redo log，不要 binlog？**

如果只从崩溃恢复的角度来讲是可以的。你可以把 binlog 关掉，这样就没有两阶段提交了，但系统依然是 crash-safe 的。

#### 正常运行中的实例，数据写入后的最终落盘，是从 redo log 更新过来的还是从 buffer pool 更新过来的呢？

* 如果是正常运行的实例的话，数据页被修改以后，跟磁盘的数据页不一致，称为脏页。最终数据落盘，就是把内存中的数据页写盘。这个过程，甚至与 redo log 毫无关系。
* 在崩溃恢复场景中，InnoDB 如果判断到一个数据页可能在崩溃恢复的时候丢失了更新，就会将它读到内存，然后让 redo log 更新内存内容。更新完成后，内存页变成脏页，就回到了第一种情况的状态。

#### redo log buffer 是什么？是先修改内存，还是先写 redo log 文件？

这个事务要往两个表中插入记录，插入数据的过程中，生成的日志都得先保存起来，但又不能在还没 commit 的时候就直接写到 redo log 文件里。

所以，redo log buffer 就是一块内存，用来先存 redo 日志的。也就是说，在执行第一个 insert 的时候，数据的内存被修改了，redo log buffer 也写入了日志。

但是，真正把日志写到 redo log 文件（文件名是 ib_logfile+ 数字），是在执行 commit 语句的时候做的。


#### WAL 机制是减少磁盘写，可是每次提交事务都要写 redo log 和 binlog，这磁盘读写次数也没变少呀？

现在你就能理解了，WAL 机制主要得益于两个方面：

1. redo log 和 binlog 都是顺序写，磁盘的顺序写比随机写速度要快；
2. 组提交机制，可以大幅度降低磁盘的 IOPS 消耗。


#### 如果你的 MySQL 现在出现了性能瓶颈，而且瓶颈在 IO 上，可以通过哪些方法来提升性能呢？

1. 设置 `binlog_group_commit_sync_delay` 和 `binlog_group_commit_sync_no_delay_count` 参数，减少 binlog 的写盘次数。这个方法是基于“额外的故意等待”来实现的，因此可能会增加语句的响应时间，但没有丢失数据的风险。
2. 将 `sync_binlog` 设置为大于 1 的值（比较常见是 100~1000）。这样做的风险是，主机掉电时会丢 `binlog` 日志。
3. 将 `innodb_flush_log_at_trx_commit` 设置为 2。这样做的风险是，主机掉电的时候会丢数据。

我不建议你把 `innodb_flush_log_at_trx_commit` 设置成 0。因为把这个参数设置成 0，表示 redo log 只保存在内存中，这样的话 MySQL 本身异常重启也会丢数据，风险太大。而 redo log 写到文件系统的 page cache 的速度也是很快的，所以将这个参数设置成 2 跟设置成 0 其实性能差不多，但这样做 MySQL 异常重启时就不会丢数据了，相比之下风险会更小。


#### 执行一个 update 语句以后，我再去执行 hexdump 命令直接查看 ibd 文件内容，为什么没有看到数据有改变呢？
这可能是因为 WAL 机制的原因。update 语句执行完成后，InnoDB 只保证写完了 redo log、内存，可能还没来得及将数据写到磁盘。


#### 为什么 binlog cache 是每个线程自己维护的，而 redo log buffer 是全局共用的？
MySQL 这么设计的主要原因是，binlog 是不能“被打断的”。一个事务的 binlog 必须连续写，因此要整个事务完成后，再一起写到文件里。
而 redo log 并没有这个要求，中间有生成的日志可以写到 redo log buffer 中。redo log buffer 中的内容还能“搭便车”，其他事务提交的时候可以被一起写到磁盘中。

这个问题，感觉还有一点，binlog存储是以statement或者row格式存储的，而redo log是以page页格式存储的。page格式，天生就是共有的，而row格式，只跟当前事务相关

#### 事务执行期间，还没到提交阶段，如果发生 crash 的话，redo log 肯定丢了，这会不会导致主备不一致呢？

不会。因为这时候 binlog 也还在 binlog cache 里，没发给备库。crash 以后 redo log 和 binlog 都没有了，从业务角度看这个事务也没有提交，所以数据是一致的。

#### 如果 binlog 写完盘以后发生 crash，这时候还没给客户端答复就重启了。等客户端再重连进来，发现事务已经提交成功了，这是不是 bug？

不是。你可以设想一下更极端的情况，整个事务都提交成功了，redo log commit 完成了，备库也收到 binlog 并执行了。但是主库和客户端网络断开了，导致事务成功的包返回不回去，这时候客户端也会收到“网络断开”的异常。这种也只能算是事务成功的，不能认为是 bug。

实际上数据库的 crash-safe 保证的是：

1. 如果客户端收到事务成功的消息，事务就一定持久化了；
2. 如果客户端收到事务失败（比如主键冲突、回滚等）的消息，事务就一定失败了；
3. 如果客户端收到“执行异常”的消息，应用需要重连后通过查询当前状态来继续后续的逻辑。此时数据库只需要保证内部（数据和日志之间，主库和备库之间）一致就可以了。

#### 为什么binlog 是不能“被打断的”的呢？主要出于什么考虑？

我觉得一个比较重要的原因是，**一个线程只能同时有一个事务在执行**。

由于这个设定，所以每当执行一个begin/start transaction的时候，就会默认提交上一个事务；
**这样如果一个事务的binlog被拆开的时候，在备库执行就会被当做多个事务分段自行，这样破坏了原子性，是有问题的**。


#### 主从循环复制问题

![image.png](https://upload-images.jianshu.io/upload_images/12321605-e4f57b051c5323e9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


1. 规定两个库的 server id 必须不同，如果相同，则它们之间不能设定为主备关系；
2. 一个备库接到 binlog 并在重放的过程中，生成与原 binlog 的 server id 相同的新的 binlog；
3. 每个库在收到从自己的主库发过来的日志后，先判断 server id，如果跟自己的相同，表示这个日志是自己生成的，就直接丢弃这个日志。

按照这个逻辑，如果我们设置了双 M 结构，日志的执行流就会变成这样：

1. 从节点 A 更新的事务，binlog 里面记的都是 A 的 server id；
2. 传到节点 B 执行一次以后，节点 B 生成的 binlog 的 server id 也是 A 的 server id；
3. 再传回给节点 A，A 判断到这个 server id 与自己的相同，就不会再处理这个日志。所以，死循环在这里就断掉了。



#### WAL(write-ahead-log)日志与回滚（rollback）日志的区别

**回滚日志：**

* 复制原始数据库内容并将其保存在单独的文件（即回滚日志）中，然后将新值写入数据库。
* 事务提交后，则删除回滚日志。
* 如果事务中止，则将回滚日志中的内容复制回数据库。

**预写日志：**

* 更改将附加到预写日志文件中。
* 提交时，会在WAL上设置“提交”标志（原始数据库此时可能不会更改）。
* 在WAL的检查点执行之前，可能会有多个已经提交的事务，但并未写入数据库物理文件。




## SQL执行过程

### 一条SQL如何执行？

![image](https://upload-images.jianshu.io/upload_images/12321605-dafc1ef4bc3a467b?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

* 连接器，连接器负责跟客户端建立连接、获取权限、维持和管理连接。`show processlist` 可以查看链接状态。客户端如果太长时间没动静，连接器就会自动将它断开。这个时间是由参数 wait_timeout 控制的，默认值是 8 小时。
* 查询缓存，MySQL 拿到一个查询请求后，会先到查询缓存看看，之前是不是执行过这条语句。之前执行过的语句及其结果可能会以 key-value 对的形式，被直接缓存在内存中。key 是查询的语句，value 是查询的结果。如果你的查询能够直接在这个缓存中找到 key，那么这个 value 就会被直接返回给客户端。
	- **但是大多数情况下我会建议你不要使用查询缓存，为什么呢？因为查询缓存往往弊大于利。**
	- 查询缓存的失效非常频繁，只要有对一个表的更新，这个表上所有的查询缓存都会被清空。因此很可能你费劲地把结果存起来，还没使用呢，就被一个更新全清空了。对于更新压力大的数据库来说，查询缓存的命中率会非常低。除非你的业务就是有一张静态表，很长时间才会更新一次。比如，一个系统配置表，那这张表上的查询才适合使用查询缓存。
	- MySQL 8.0 版本直接将查询缓存的整块功能删掉了。
* 分析器，主要对SQl做词法分析和语法分析，检查语法错误。
* 优化器，优化器是在表里面有多个索引的时候，决定使用哪个索引；或者在一个语句有多表关联（join）的时候，决定各个表的连接顺序。
* 执行器，执行相关操作。

### 一个SQL 更新过程

	mysql> update T set c=c+1 where ID=2;


这里我给出这个 update 语句的执行流程图，图中浅色框表示是在 InnoDB 内部执行的，深色框表示是在执行器中执行的。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-8e2cc83183584ada.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)



#### change buffer

当需要更新一个数据页时，如果数据页在内存中就直接更新，而如果这个数据页还没有在内存中的话，在不影响数据一致性的前提下，InnoDB 会将这些更新操作缓存在 change buffer 中，这样就不需要从磁盘中读入这个数据页了。在下次查询需要访问这个数据页的时候，将数据页读入内存，然后执行 change buffer 中与这个页有关的操作。通过这种方式就能保证这个数据逻辑的正确性。

需要说明的是，虽然名字叫作 change buffer，实际上它是可以持久化的数据。也就是说，change buffer 在内存中有拷贝，也会被写入到磁盘上。

将 change buffer 中的操作应用到原数据页，得到最新结果的过程称为 merge。除了访问这个数据页会触发 merge 外，系统有后台线程会定期 merge。在数据库正常关闭（shutdown）的过程中，也会执行 merge 操作。

显然，如果能够将更新操作先记录在 change buffer，减少读磁盘，语句的执行速度会得到明显的提升。而且，数据读入内存是需要占用 buffer pool 的，所以这种方式还能够避免占用内存，提高内存利用率。

那么，**什么条件下可以使用 change buffer 呢？**

对于唯一索引来说，所有的更新操作都要先判断这个操作是否违反唯一性约束。比如，要插入 (4,400) 这个记录，就要先判断现在表中是否已经存在 k=4 的记录，**而这必须要将数据页读入内存才能判断**。如果都已经读入到内存了，那直接更新内存会更快，就没必要使用 change buffer 了。

change buffer 用的是 buffer pool 里的内存，因此不能无限增大。change buffer 的大小，可以通过参数 `innodb_change_buffer_max_size` 来动态设置。这个参数设置为 50 的时候，表示 change buffer 的大小最多只能占用 buffer pool 的 50%。

现在，你已经理解了 change buffer 的机制，那么我们再一起来看看如果要在这张表中插入一个新记录 (4,400) 的话，InnoDB 的处理流程是怎样的。

第一种情况是，这个记录要更新的目标页在内存中。这时，InnoDB 的处理流程如下：

* 对于唯一索引来说，找到 3 和 5 之间的位置，判断到没有冲突，插入这个值，语句执行结束；
* 对于普通索引来说，找到 3 和 5 之间的位置，插入这个值，语句执行结束。

这样看来，普通索引和唯一索引对更新语句性能影响的差别，只是一个判断，只会耗费微小的 CPU 时间。

第二种情况是，这个记录要更新的目标页不在内存中。

这时，InnoDB 的处理流程如下：

* 对于唯一索引来说，需要将数据页读入内存，判断到没有冲突，插入这个值，语句执行结束；
* 对于普通索引来说，则是将更新记录在 change buffer，语句执行就结束了。

将数据从磁盘读入内存涉及随机 IO 的访问，是数据库里面成本最高的操作之一。change buffer 因为减少了随机磁盘访问，所以对更新性能的提升是会很明显的。

之前我就碰到过一件事儿，有个 DBA 的同学跟我反馈说，他负责的某个业务的库内存命中率突然从 99% 降低到了 75%，整个系统处于阻塞状态，更新语句全部堵住。而探究其原因后，我发现这个业务有大量插入数据的操作，而他在前一天把其中的某个普通索引改成了唯一索引。


#### change buffer 的使用场景

通过上面的分析，你已经清楚了使用 change buffer 对更新过程的加速作用，也清楚了 change buffer 只限于用在普通索引的场景下，而不适用于唯一索引。那么，现在有一个问题就是：普通索引的所有场景，使用 change buffer 都可以起到加速作用吗？

因为 merge 的时候是真正进行数据更新的时刻，而 change buffer 的主要目的就是将记录的变更动作缓存下来，所以在一个数据页做 merge 之前，change buffer 记录的变更越多（也就是这个页面上要更新的次数越多），收益就越大。

因此，对于**写多读少的业务来说**，页面在写完以后马上被访问到的概率比较小，此时 change buffer 的使用效果最好。这种业务模型常见的就是账单类、日志类的系统。

反过来，假设一个业务的**更新模式是写入之后马上会做查询**，那么即使满足了条件，将更新先记录在 change buffer，但之后由于马上要访问这个数据页，会立即触发 merge 过程。这样随机访问 IO 的次数不会减少，反而增加了 change buffer 的维护代价。所以，对于这种业务模式来说，**change buffer 反而起到了副作用**。


### 一个 SQL 查询过程

假设，执行查询的语句是 select id from T where k=5。这个查询语句在索引树上查找的过程，先是通过 B+ 树从树根开始，按层搜索到叶子节点，也就是图中右下角的这个数据页，然后可以认为数据页内部通过二分法来定位记录。

* 对于普通索引来说，查找到满足条件的第一个记录 (5,500) 后，需要查找下一个记录，直到碰到第一个不满足 k=5 条件的记录。
* 对于唯一索引来说，由于索引定义了唯一性，查找到第一个满足条件的记录后，就会停止继续检索。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-5880ac0b4e638c14.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

那么，这个不同带来的性能差距会有多少呢？答案是，微乎其微。

你知道的，InnoDB 的数据是按数据页为单位来读写的。也就是说，当需要读一条记录的时候，并不是将这个记录本身从磁盘读出来，而是以页为单位，将其整体读入内存。在 InnoDB 中，每个数据页的大小默认是 16KB。

因为引擎是按页读写的，所以说，当找到 k=5 的记录的时候，它所在的数据页就都在内存里了。那么，对于普通索引来说，要多做的那一次“查找和判断下一条记录”的操作，就只需要一次指针寻找和一次计算。

当然，如果 k=5 这个记录刚好是这个数据页的最后一个记录，那么要取下一个记录，必须读取下一个数据页，这个操作会稍微复杂一些。

但是，我们之前计算过，对于整型字段，一个数据页可以放近千个 key，因此出现这种情况的概率会很低。所以，我们计算平均性能差异时，仍可以认为这个操作成本对于现在的 CPU 来说可以忽略不计。


#### 缓冲池(buffer pool)

内存的数据页是在 Buffer Pool (BP) 中管理的，在 WAL 里 Buffer Pool 起到了加速更新的作用。而实际上，Buffer Pool 还有一个更重要的作用，就是加速查询。

InnoDB 内存管理用的是最近最少使用 (Least Recently Used, LRU) 算法，这个算法的核心就是淘汰最久未使用的数据。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-cf5917f5d50a3516.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


1. 将LRU分为两个部分： 新生代(new sublist) 老生代(old sublist) 
2. 新老生代收尾相连，即：新生代的尾(tail)连接着老生代的头(head)； 
3. 新页（例如被预读的页）加入缓冲池时，只加入到老生代头部： 如果数据真正被读取（预读成功），才会加入到新生代的头部 如果数据没有被读取，则会比新生代里的“热数据页”更早被淘汰出缓冲池

线上库 buffer pool 64G

	show variables like '%join_buffer_size%';  //8M
	show variables like '%sort_buffer_size%'; //8M
	show variables like '%innodb_buffer_pool_size%'; // 64G


#### 索引下推


	mysql> select * from tuser where name like '张%' and age=10 and ismale=1;


![无索引下推执行流程](https://upload-images.jianshu.io/upload_images/12321605-32c099559ba3e868.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


![索引下推执行流程](https://upload-images.jianshu.io/upload_images/12321605-333bf3f31548787f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)




### Mysql优化器

而优化器选择索引的目的，是找到一个最优的执行方案，并用最小的代价去执行语句。在数据库里面，扫描行数是影响执行代价的因素之一。扫描的行数越少，意味着访问磁盘数据的次数越少，消耗的 CPU 资源越少。

当然，扫描行数并不是唯一的判断标准，优化器还会结合是否使用临时表、是否排序等因素进行综合判断。

我们这个简单的查询语句并没有涉及到临时表和排序，所以 MySQL 选错索引肯定是在判断扫描行数的时候出问题了。

那么，问题就是：**扫描行数是怎么判断的？**

这个统计信息就是索引的“**区分度**”。显然，一个索引上不同的值越多，这个索引的区分度就越好。而一个索引上不同的值的个数，我们称之为“基数”（cardinality）。也就是说，这个基数越大，索引的区分度越好。

我们可以使用 show index 方法，看到一个索引的基数。如图所示，就是表 t 的 show index 的结果 。虽然这个表的每一行的三个字段值都是一样的，但是在统计信息中，这三个索引的基数值并不同，而且其实都不准确。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-66b22725a0460116.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


那么，MySQL 是怎样得到索引的基数的呢？这里，我给你简单介绍一下 MySQL 采样统计的方法。

为什么要采样统计呢？因为把整张表取出来一行行统计，虽然可以得到精确的结果，但是代价太高了，所以只能选择“采样统计”。

采样统计的时候，InnoDB 默认会选择 N 个数据页，统计这些页面上的不同值，得到一个平均值，然后乘以这个索引的页面数，就得到了这个索引的基数。

而数据表是会持续更新的，索引统计信息也不会固定不变。所以，当变更的数据行数超过 1/M 的时候，会自动触发重新做一次索引统计。

在 MySQL 中，有两种存储索引统计的方式，可以通过设置参数 `innodb_stats_persistent` 的值来选择：

* 设置为 on 的时候，表示统计信息会持久化存储。这时，默认的 N 是 20，M 是 10。
* 设置为 off 的时候，表示统计信息只存储在内存中。这时，默认的 N 是 8，M 是 16。

**既然是统计信息不对，那就修正。analyze table t 命令，可以用来重新统计索引信息。我们来看一下执行效果。**


#### 索引选择异常和处理

1. 一种方法是，像我们第一个例子一样，采用 force index 强行选择一个索引。MySQL 会根据词法解析的结果分析出可能可以使用的索引作为候选项，然后在候选列表中依次判断每个索引需要扫描多少行。如果 force index 指定的索引在候选索引列表中，就直接选择这个索引，不再评估其他索引的执行代价。
2. 既然优化器放弃了使用索引 a，说明 a 还不够合适，所以第二种方法就是，我们可以考虑修改语句，引导 MySQL 使用我们期望的索引。比如，在这个例子里，显然把“order by b limit 1” 改成 “order by b,a limit 1” ，语义的逻辑是相同的。
3. 第三种方法是，在有些场景下，我们可以新建一个更合适的索引，来提供给优化器做选择，或删掉误用的索引。第三种方法是，在有些场景下，我们可以新建一个更合适的索引，来提供给优化器做选择，或删掉误用的索引。


#### 字符串索引存储

但是，索引选取的越长，占用的磁盘空间就越大，相同的数据页能放下的索引值就越少，搜索的效率也就会越低。


第一种方式是使用倒序存储。如果你存储身份证号的时候把它倒过来存，每次查询的时候，你可以这么写：


	mysql> select field_list from t where id_card = reverse('input_id_card_string');


第二种方式是使用 hash 字段。你可以在表上再创建一个整数字段，来保存身份证的校验码，同时在这个字段上创建索引。

	mysql> alter table t add id_card_crc int unsigned, add index(id_card_crc);

它们的区别，主要体现在以下三个方面：

1. 从占用的额外空间来看，倒序存储方式在主键索引上，不会消耗额外的存储空间，而 hash 字段方法需要增加一个字段。当然，倒序存储方式使用 4 个字节的前缀长度应该是不够的，如果再长一点，这个消耗跟额外这个 hash 字段也差不多抵消了。
2. 在 CPU 消耗方面，倒序方式每次写和读的时候，都需要额外调用一次 reverse 函数，而 hash 字段的方式需要额外调用一次 crc32() 函数。如果只从这两个函数的计算复杂度来看的话，reverse 函数额外消耗的 CPU 资源会更小些。
3. 从查询效率上看，使用 hash 字段方式的查询性能相对更稳定一些。因为 crc32 算出来的值虽然有冲突的概率，但是概率非常小，可以认为每次查询的平均扫描行数接近 1。而倒序存储方式毕竟还是用的前缀索引的方式，也就是说还是会增加扫描行数。


#### 最左前缀原则

这里，我先和你说结论吧。B+ 树这种索引结构，可以利用索引的“最左前缀”，来定位记录。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-967b2dbcda2bbc62.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

### 脏页

当内存数据页跟磁盘数据页内容不一致的时候，我们称这个内存页为“脏页”。内存数据写入到磁盘后，内存和磁盘上的数据页的内容就一致了，称为“干净页”。**部分刷账页可能导致Mysql抖动**。

#### 强制刷脏页的场景

1. InnoDB 的 redo log 写满了。这时候系统会停止所有更新操作，把 checkpoint 往前推进，redo log 留出空间可以继续写。
2. 系统内存不足。当需要新的内存页，而内存不够用的时候，就要淘汰一些数据页，空出内存给别的数据页使用。如果淘汰的是“脏页”，就要先将脏页写到磁盘。你一定会说，这时候难道不能直接把内存淘汰掉，下次需要请求的时候，从磁盘读入数据页，然后拿 redo log 出来应用不就行了？这里其实是从性能考虑的。如果刷脏页一定会写盘，就保证了每个数据页有两种状态：
   - 一种是内存里存在，内存里就肯定是正确的结果，直接返回；
   - 另一种是内存里没有数据，就可以肯定数据文件上是正确的结果，读入内存后返回。这样的效率最高。
3. MySQL 认为系统“空闲”的时候。当然，MySQL“这家酒店”的生意好起来可是会很快就能把粉板记满的，所以“掌柜”要合理地安排时间，即使是“生意好”的时候，也要见缝插针地找时间，只要有机会就刷一点“脏页”。
4. MySQL 正常关闭的情况。这时候，MySQL 会把内存的脏页都 flush 到磁盘上，这样下次 MySQL 启动的时候，就可以直接从磁盘上读数据，启动速度会很快。

第一种是“redo log 写满了，要 flush 脏页”，这种情况是 InnoDB 要尽量避免的。因为出现这种情况的时候，整个系统就不能再接受更新了，所有的更新都必须堵住。如果你从监控上看，这时候更新数会跌为 0。


第二种是“内存不够用了，要先将脏页写到磁盘”，这种情况其实是常态。InnoDB 用缓冲池（buffer pool）管理内存，缓冲池中的内存页有三种状态：

* 第一种是，还没有使用的；
* 第二种是，使用了并且是干净页；
* 第三种是，使用了并且是脏页。

而当要读入的数据页没有在内存的时候，就必须到缓冲池中申请一个数据页。这时候只能把最久不使用的数据页从内存中淘汰掉：如果要淘汰的是一个干净页，就直接释放出来复用；但如果是脏页呢，就必须将脏页先刷到磁盘，变成干净页后才能复用。

所以，刷脏页虽然是常态，但是出现以下这两种情况，都是会明显影响性能的：

* 一个查询要淘汰的脏页个数太多，会导致查询的响应时间明显变长；
* 日志写满，更新全部堵住，写性能跌为 0，这种情况对敏感业务来说，是不能接受的。

#### 刷脏页速度

这就要用到 innodb_io_capacity 这个参数了，它会告诉 InnoDB 你的磁盘能力。这个值我建议你设置成磁盘的 IOPS。磁盘的 IOPS 可以通过 fio 这个工具来测试，下面的语句是我用来测试磁盘随机读写的命令：

然后，根据上述算得的 F1(M) 和 F2(N) 两个值，取其中较大的值记为 R，之后引擎就可以按照 innodb_io_capacity 定义的能力乘以 R% 来控制刷脏页的速度。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-21b882b7aa3fe317.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


### 其他问题

#### 覆盖索引

覆盖索引是指，索引上的信息足够满足查询请求，不需要再回到主键索引上去取数据。

#### 当 MySQL 去更新一行，但是要修改的值跟原来的值是相同的，这时候 MySQL 会真的去执行一次修改吗？

https://time.geekbang.org/column/article/73479

InnoDB 认真执行了“把这个值修改成 (1,2)"这个操作，该加锁的加锁，该更新的更新。


#### 我查这么多数据，会不会把数据库内存打爆

我经常会被问到这样一个问题：我的主机内存只有 100G，现在要对一个 200G 的大表做全表扫描，会不会把数据库主机的内存用光了？

实际上，服务端并不需要保存一个完整的结果集。取数据和发数据的流程是这样的：

1. 获取一行，写到 `net_buffer` 中。这块内存的大小是由参数 `net_buffer_length` 定义的，默认是 16k。
2. 重复获取行，直到 `net_buffer` 写满，调用网络接口发出去。
3. 如果发送成功，就清空 `net_buffer`，然后继续取下一行，并写入 `net_buffer`。
4. 如果发送函数返回 `EAGAIN` 或 `WSAEWOULDBLOCK`，就表示本地网络栈（socket send buffer）写满了，进入等待。直到网络栈重新可写，再继续发送。

也就是说，MySQL 是“**边读边发的**”，这个概念很重要。这就意味着，如果客户端接收得慢，会导致 MySQL 服务端由于结果发不出去，这个事务的执行时间变长。


#### 读写分离 - 过期读问题

这种“在从库上会读到系统的一个过期状态”的现象，在这篇文章里，我们暂且称之为“过期读”。
不论哪种结构，客户端都希望查询从库的数据结果，跟查主库的数据结果是一样的。

1. 强制走主库方案；
2. sleep 方案；
3. 判断主备无延迟方案； `show slave status` ，判断 seconds_behind_master 是否已经等于 0。如果还不等于 0 ，那就必须等到这个参数变为 0 才能执行查询请求。
4. 配合 semi-sync 方案，要解决这个问题，就要引入半同步复制，也就是 semi-sync replication，
  - 事务提交的时候，主库把 binlog 发给从库；
  - 从库收到 binlog 以后，发回给主库一个 ack，表示收到了；
  - 主库收到这个 ack 以后，才能给客户端返回“事务完成”的确认。
  - 也就是说，如果启用了 semi-sync，就表示所有给客户端发送过确认的事务，都确保了备库已经收到了这个日志。
5. 等主库位点方案；
   - Master_Log_File 和 Read_Master_Log_Pos，表示的是读到的主库的最新位点；
   - Relay_Master_Log_File 和 Exec_Master_Log_Pos，表示的是备库执行的最新位点。
   - 如果 Master_Log_File 和 Relay_Master_Log_File、Read_Master_Log_Pos 和Exec_Master_Log_Pos 这两组值完全相同，就表示接收到的日志已经同步完成。
6. 等 GTID 方案，对比 GTID 集合确保主备无延迟。
   - Auto_Position=1 ，表示这对主备关系使用了 GTID 协议。
   - Retrieved_Gtid_Set，是备库收到的所有日志的 GTID 集合；
   - Executed_Gtid_Set，是备库所有已经执行完成的 GTID 集合。


但是，semi-sync+ 位点判断的方案，只对一主一备的场景是成立的。在一主多从场景中，主库只要等到一个从库的 ack，就开始给客户端返回确认。这时，在从库上执行查询请求，就有两种情况：

1. 如果查询是落在这个响应了 ack 的从库上，是能够确保读到最新数据；
2. 但如果是查询落到其他从库上，它们可能还没有收到最新的日志，就会产生过期读的问题。


### 事务

### 当前读 ，快照读

![image.png](https://upload-images.jianshu.io/upload_images/12321605-24255ed96a43bc71.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![image.png](https://upload-images.jianshu.io/upload_images/12321605-4d43ad08b8f23326.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

#### 事务隔离

这样，对于当前事务的启动瞬间来说，一个数据版本的 row trx_id，有以下几种可能：

1. 如果落在绿色部分，表示这个版本是已提交的事务或者是当前事务自己生成的，这个数据是可见的；
2. 如果落在红色部分，表示这个版本是由将来启动的事务生成的，是肯定不可见的；
3. 如果落在黄色部分，那就包括两种情况
   - a.  若 row trx_id 在数组中，表示这个版本是由还没提交的事务生成的，不可见；
   - b.  若 row trx_id 不在数组中，表示这个版本是已经提交了的事务生成的，可见。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-4951deb7d23236a6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

一个数据版本，对于一个事务视图来说，除了自己的更新总是可见以外，有三种情况：

1. 版本未提交，不可见；
2. 版本已提交，但是是在视图创建后提交的，不可见；
3. 版本已提交，而且是在视图创建前提交的，可见。


## 锁

###  加锁原则

我总结的加锁规则里面，包含了两个“原则”、两个“优化”和一个“bug”。 

* 原则 1：加锁的基本单位是 next-key lock。希望你还记得，next-key lock 是前开后闭区间。
* 原则 2：查找过程中访问到的对象才会加锁。
* 优化 1：索引上的等值查询，给唯一索引加锁的时候，next-key lock 退化为行锁。
* 优化 2：索引上的等值查询，向右遍历时且最后一个值不满足等值条件的时候，next-key lock 退化为间隙锁。
* 一个 bug：唯一索引上的范围查询会访问到不满足条件的第一个值为止。

https://time.geekbang.org/column/article/75659


### 锁粒度

#### 全局锁

全局锁顾名思义，全局锁就是对整个数据库实例加锁。MySQL 提供了一个加全局读锁的方法，命令是 Flush tables with read lock (FTWRL)。当你需要让整个库处于只读状态的时候，可以使用这个命令，之后其他线程的以下语句会被阻塞：数据更新语句（数据的增删改）、数据定义语句（包括建表、修改表结构等）和更新类事务的提交语句。

全局锁的典型使用场景是，做全库逻辑备份。也就是把整库每个表都 select 出来存成文本。

##### 备份

官方自带的逻辑备份工具是 mysqldump。当 mysqldump 使用参数–single-transaction 的时候，导数据之前就会启动一个事务，来确保拿到一致性视图。而由于 MVCC 的支持，这个过程中数据是可以正常更新的。

所以，**single-transaction 方法只适用于所有的表使用事务引擎的库**。如果有的表使用了不支持事务的引擎，那么备份就只能通过 FTWRL 方法。这往往是 DBA 要求业务开发人员使用 InnoDB 替代 MyISAM 的原因之一。

你也许会问，既然要全库只读，为什么不使用 set global readonly=true 的方式呢？确实 readonly 方式也可以让全库进入只读状态，但我还是会建议你用 FTWRL 方式，主要有两个原因：

* 一是，在有些系统中，readonly 的值会被用来做其他逻辑，比如用来判断一个库是主库还是备库。因此，修改 global 变量的方式影响面更大，我不建议你使用。
* 二是，在异常处理机制上有差异。如果执行 FTWRL 命令之后由于客户端发生异常断开，那么 MySQL 会自动释放这个全局锁，整个库回到可以正常更新的状态。而将整个库设置为 readonly 之后，如果客户端发生异常，则数据库就会一直保持 readonly 状态，这样会导致整个库长时间处于不可写状态，风险较高。

#### 表级别锁

MySQL 里面表级别的锁有两种：一种是表锁，一种是元数据锁（meta data lock，MDL)。

表锁的语法是 lock tables … read/write。与 FTWRL 类似，可以用 unlock tables 主动释放锁，也可以在客户端断开的时候自动释放。需要注意，lock tables 语法除了会限制别的线程的读写外，也限定了本线程接下来的操作对象。

举个例子, 如果在某个线程 A 中执行 lock tables t1 read, t2 write; 这个语句，则其他线程写 t1、读写 t2 的语句都会被阻塞。同时，线程 A 在执行 unlock tables 之前，也只能执行读 t1、读写 t2 的操作。连写 t1 都不允许，自然也不能访问其他表。


另一类表级的锁是 MDL（metadata lock)。MDL 不需要显式使用，在访问一个表的时候会被自动加上。MDL 的作用是，保证读写的正确性。你可以想象一下，如果一个查询正在遍历一个表中的数据，而执行期间另一个线程对这个表结构做变更，删了一列，那么查询线程拿到的结果跟表结构对不上，肯定是不行的。

* 因此，在 MySQL 5.5 版本中引入了 MDL，当对一个表做增删改查操作的时候，加 MDL 读锁；当要对表做结构变更操作的时候，加 MDL 写锁。
* 读锁之间不互斥，因此你可以有多个线程同时对一张表增删改查。读写锁之间、写锁之间是互斥的，用来保证变更表结构操作的安全性。因此，如果有两个线程要同时给一个表加字段，其中一个要等另一个执行完才能开始执行。


MDL 会直到事务提交才释放，在做表结构变更的时候，你一定要小心不要导致锁住线上查询和更新。


![image.png](https://upload-images.jianshu.io/upload_images/12321605-1ccbea6c67cff98e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

我们可以看到 session A 先启动，这时候会对表 t 加一个 MDL 读锁。由于 session B 需要的也是 MDL 读锁，因此可以正常执行。

之后 session C 会被 blocked，是因为 session A 的 MDL 读锁还没有释放，而 session C 需要 MDL 写锁，因此只能被阻塞。

如果只有 session C 自己被阻塞还没什么关系，但是之后所有要在表 t 上新申请 MDL 读锁的请求也会被 session C 阻塞。前面我们说了，所有对表的增删改查操作都需要先申请 MDL 读锁，就都被锁住，等于这个表现在完全不可读写了。


### 两阶段锁

![image.png](https://upload-images.jianshu.io/upload_images/12321605-e92660ddd0e713a3.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


也就是说，在 InnoDB 事务中，行锁是在需要的时候才加上的，但并不是不需要了就立刻释放，而是要等到事务结束时才释放。这个就是两阶段锁协议。

### 死锁和死锁检测

![image.png](https://upload-images.jianshu.io/upload_images/12321605-64e9193bd1a3063e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

这时候，事务 A 在等待事务 B 释放 id=2 的行锁，而事务 B 在等待事务 A 释放 id=1 的行锁。 事务 A 和事务 B 在互相等待对方的资源释放，就是进入了死锁状态。当出现死锁以后，有两种策略：

* 一种策略是，直接进入等待，直到超时。这个超时时间可以通过参数 innodb_lock_wait_timeout 来设置。
* 另一种策略是，发起死锁检测，发现死锁后，主动回滚死锁链条中的某一个事务，让其他事务得以继续执行。将参数 innodb_deadlock_detect 设置为 on，表示开启这个逻辑。

#### select 和 insert死锁场景

![image.png](https://upload-images.jianshu.io/upload_images/12321605-0a3fb6f1da08a56b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


你看到了，其实都不需要用到后面的 update 语句，就已经形成死锁了。我们按语句执行顺序来分析一下：

* session A 执行 select … for update 语句，由于 id=9 这一行并不存在，因此会加上间隙锁 (5,10);
* session B 执行 select … for update 语句，同样会加上间隙锁 (5,10)，间隙锁之间不会冲突，因此这个语句可以执行成功；
* session B 试图插入一行 (9,9,9)，被 session A 的间隙锁挡住了，只好进入等待；
* session A 试图插入一行 (9,9,9)，被 session B 的间隙锁挡住了。


### 热点行问题

那如果是我们上面说到的所有事务都要更新同一行的场景呢？
每个新来的被堵住的线程，都要判断会不会由于自己的加入导致了死锁，这是一个时间复杂度是 O(n) 的操作。假设有 1000 个并发线程要同时更新同一行，那么死锁检测操作就是 100 万这个量级的。虽然最终检测的结果是没有死锁，但是这期间要消耗大量的 CPU 资源。因此，你就会看到 CPU 利用率很高，但是每秒却执行不了几个事务。

根据上面的分析，我们来讨论一下，**怎么解决由这种热点行更新导致的性能问题呢**？问题的症结在于，死锁检测要耗费大量的 CPU 资源。

* 一种头痛医头的方法，就是如果你能确保这个业务一定不会出现死锁，可以临时把死锁检测关掉。但是这种操作本身带有一定的风险，因为业务设计的时候一般不会把死锁当做一个严重错误，毕竟出现死锁了，就回滚，然后通过业务重试一般就没问题了，这是业务无损的。而关掉死锁检测意味着可能会出现大量的超时，这是业务有损的。
* 另一个思路是控制并发度。根据上面的分析，你会发现如果并发能够控制住，比如同一行同时最多只有 10 个线程在更新，那么死锁检测的成本很低，就不会出现这个问题。一个直接的想法就是，在客户端做并发控制。但是，你会很快发现这个方法不太可行，因为客户端很多。我见过一个应用，有 600 个客户端，这样即使每个客户端控制到只有 5 个并发线程，汇总到数据库服务端以后，峰值并发数也可能要达到 3000。

因此，这个并发控制要做在数据库服务端。如果你有中间件，可以考虑在中间件实现；如果你的团队有能修改 MySQL 源码的人，也可以做在 MySQL 里面。基本思路就是，对于相同行的更新，在进入引擎之前排队。这样在 InnoDB 内部就不会有大量的死锁检测工作了。

要访问的行上有锁，他才要死锁检测。



