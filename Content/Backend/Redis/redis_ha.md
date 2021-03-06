# Redis 高可用解决方案总结

- [Redis 高可用解决方案总结](#redis-%e9%ab%98%e5%8f%af%e7%94%a8%e8%a7%a3%e5%86%b3%e6%96%b9%e6%a1%88%e6%80%bb%e7%bb%93)
	- [一、主从复制](#%e4%b8%80%e4%b8%bb%e4%bb%8e%e5%a4%8d%e5%88%b6)
		- [什么是主从复制](#%e4%bb%80%e4%b9%88%e6%98%af%e4%b8%bb%e4%bb%8e%e5%a4%8d%e5%88%b6)
		- [主从复制过程](#%e4%b8%bb%e4%bb%8e%e5%a4%8d%e5%88%b6%e8%bf%87%e7%a8%8b)
			- [增量复制](#%e5%a2%9e%e9%87%8f%e5%a4%8d%e5%88%b6)
			- [断点续传（continue replication）](#%e6%96%ad%e7%82%b9%e7%bb%ad%e4%bc%a0continue-replication)
			- [PSYNC 核心参数](#psync-%e6%a0%b8%e5%bf%83%e5%8f%82%e6%95%b0)
		- [优缺点](#%e4%bc%98%e7%bc%ba%e7%82%b9)
	- [二、Redis 哨兵 (Redis Sentinel)](#%e4%ba%8credis-%e5%93%a8%e5%85%b5-redis-sentinel)
		- [什么是哨兵](#%e4%bb%80%e4%b9%88%e6%98%af%e5%93%a8%e5%85%b5)
		- [基本的故障转移流程](#%e5%9f%ba%e6%9c%ac%e7%9a%84%e6%95%85%e9%9a%9c%e8%bd%ac%e7%a7%bb%e6%b5%81%e7%a8%8b)
		- [注意事项](#%e6%b3%a8%e6%84%8f%e4%ba%8b%e9%a1%b9)
		- [优缺点](#%e4%bc%98%e7%bc%ba%e7%82%b9-1)
	- [三、Redis 集群 （Redis Cluster）](#%e4%b8%89redis-%e9%9b%86%e7%be%a4-redis-cluster)
		- [什么是 Redis 集群](#%e4%bb%80%e4%b9%88%e6%98%af-redis-%e9%9b%86%e7%be%a4)
		- [集群的模型](#%e9%9b%86%e7%be%a4%e7%9a%84%e6%a8%a1%e5%9e%8b)
		- [各个节点之间都传递了什么信息](#%e5%90%84%e4%b8%aa%e8%8a%82%e7%82%b9%e4%b9%8b%e9%97%b4%e9%83%bd%e4%bc%a0%e9%80%92%e4%ba%86%e4%bb%80%e4%b9%88%e4%bf%a1%e6%81%af)
		- [Hash 槽(slot)](#hash-%e6%a7%bdslot)
		- [容错](#%e5%ae%b9%e9%94%99)
		- [优缺点](#%e4%bc%98%e7%bc%ba%e7%82%b9-2)
	- [四、Redis 自研高可用架构](#%e5%9b%9bredis-%e8%87%aa%e7%a0%94%e9%ab%98%e5%8f%af%e7%94%a8%e6%9e%b6%e6%9e%84)
	- [五、Redis 代理中间件](#%e4%ba%94redis-%e4%bb%a3%e7%90%86%e4%b8%ad%e9%97%b4%e4%bb%b6)
		- [Codis](#codis)
			- [什么是 Codis](#%e4%bb%80%e4%b9%88%e6%98%af-codis)
			- [Codis 分片原理](#codis-%e5%88%86%e7%89%87%e5%8e%9f%e7%90%86)
			- [Codis 之间的槽位同步](#codis-%e4%b9%8b%e9%97%b4%e7%9a%84%e6%a7%bd%e4%bd%8d%e5%90%8c%e6%ad%a5)
			- [Codis 中的扩容](#codis-%e4%b8%ad%e7%9a%84%e6%89%a9%e5%ae%b9)
			- [自动均衡策略](#%e8%87%aa%e5%8a%a8%e5%9d%87%e8%a1%a1%e7%ad%96%e7%95%a5)
			- [Codis 的牺牲](#codis-%e7%9a%84%e7%89%ba%e7%89%b2)
			- [MGET 的过程](#mget-%e7%9a%84%e8%bf%87%e7%a8%8b)
			- [Codis 集群总结](#codis-%e9%9b%86%e7%be%a4%e6%80%bb%e7%bb%93)
		- [Twemproxy 代理](#twemproxy-%e4%bb%a3%e7%90%86)
			- [什么是 Twemproxy](#%e4%bb%80%e4%b9%88%e6%98%af-twemproxy)
		- [Twemproxy 特性](#twemproxy-%e7%89%b9%e6%80%a7)
	- [参考文章](#%e5%8f%82%e8%80%83%e6%96%87%e7%ab%a0)

## 一、主从复制

### 什么是主从复制

我们正常在项目中对`redis`进行应用，一般都不会是单点的。因为，单点的宕机即不可用，不能保证可用性。另外，单点`redis`读写指令都会打到同一个服务里面，也会影响性能。在通常的应用中，对`redis`的读操作远远多于写操作，所以，我们一般会选择“一主多从”的集群策略。

<img src="../images/redis_ha.jpg" width="300" hegiht="203" align=center />

- 主中的数据有两个副本（`replication`）即从`redis1`和从`redis2`，即使一台服务器宕机其它两台服务也可以继续提供服务。
- 主中的数据和从上的数据保持实时同步，当主写入数据时通过主从复制机制会复制到两个从服务上。
- 只有一个主`redis`，可以有多个从 `redis`。
- 主从复制不会阻塞`master`，在同步数据时，`master`可以继续处理`client`请求。

一个可以即是主又是从，如下图：

<img src="../images/redis_ha2.jpg" width="400" hegiht="203" align=center />

### 主从复制过程

一般当`slave`第一次启动连接`master`，或者“被认为是第一次连接”，是主从采用全量复制。全量复制的执行流程如下：

0. `slave redis`启动. 会从`redis.conf`中读取`master ip`和`host`。
1. 定时任务每秒检查是否有新的`mater`需要连接，如果发现就与`master`建立`socket`连接。
1. `slave`发送`ping`指令到`mater`。
1. 如果`mater`配置`require pass`，`slave`需要发送认证给`master`。
1. `Salve`会发送`sync`命令到`Master`。
1. `Master`启动一个后台进程，将`Redis`中的数据快照`rdb`保存到文件中。
1. 启动后台进程的同时，`Master`会将保存数据快照期间接收到的写命令缓存起来。
1. `Master`完成写文件操作后，将`rdb`发送给`Salve`。
1. `Salve`将`rdb`保存到磁盘上，然后加载`rdb`到`redis`内存中。
1. 当`Salve`完成数据快照的恢复后，`aster`将这期间收集的写命令发送给`Salve`端。
1. 后续`Master`收集到的写命令都会通过之前建立的连接. 增量发送给`salve`端。

调用流程图如下：

![](../images/redis_ha3.png)

#### 增量复制

当`slave`节点与`master`全量同步后，`master`节点上数据再次发生更新，就会触发增量复制。

当我们在 `master` 服务器增减数据的时候，就会触发 `replicationFeedSalves()`函数，接下来在 `Master` 服务器上调用的每一个命令都会使用`replicationFeedSlaves()` 函数来同步到`Slave`服务器。当然，在执行此函数之前`master`服务器会判断用户执行的命令是否有数据更新，如果有数据更新并且`slave`服务器不为空，才会执行此函数，函数主要的工作就是把用户执行的命令发送到所有的 `slave`服务器，让`slave`服务器执行。
流程如下图：

![](../images/redis_ha5.png)

#### 断点续传（continue replication）

断点续传或者说是断点恢复复制，也就是说 slave 因为某种原因与`master`断开连接了一段时间，然后又与`master`发生重连。`redis2.8`以后对于这种场景进行了优化，开始加入了`PSYNC`同步策略。这种策略性能一定是大于全量复制的。

1. 从服务器向主服务器发送`PSYNC`命令，携带主服务器的`runid`和复制偏移量；
2. 主服务器验证`runid`和自身`runid`是否一致，如不一致，则进行全量复制；
3. 主服务器验证复制偏移量是否在积压缓冲区内，如不在，则进行全量复制；
4. 如都验证通过，则主服务器将保持在积压区内的偏移量后的所有数据发送给从服务器，主从服务器再次回到一致状态。

![](../images/redis_ha6.png)

#### PSYNC 核心参数

介绍一下，断点续传的几个核心参数，`offset`、`backlog`、`runid`。这三个参数在 PSYNC 中起到了至关重要的作用，下面我们来一一介绍一下。

- `offet`复制偏移量 , `offset`是用来记录`master`和`lslave`某个时段的数据版本状态的，`slave`每秒会向`master`上报`offset`，`master`保存下来，当触发 PSYNC 时再拿来和`master`的`offset`数据作对比。说白了，它就是记录数据在某一时刻的快照，用来对比 master 和 slave 数据差异用的。
- `backlog`积压缓冲区
	1. 这个也是一个非常核心的参数，它默认大小为`1mb`，复制积压缓冲区是由`Master`维护的一个固定长度的`FIFO`队列，它的作用是缓存已经传播出去的命令。当`Master`进行命令传播时，不仅将命令发送给所有`Slave`，还会将命令写入到复制积压缓冲区里面。
	2. 全量复制的时候，`master`的数据更新（读写操作，主动过期删除等）会临时存放在`backlog`中待全量复制完成后增量发到slave，必须为此保留足够的空间。
	3. 断点续传时，`backlog`会存下`slave`断开连接后，`master`变更的数据。当然由于它大小有限制，而且先进先出特性，所以达到缓冲大小后会弹出老数据。这样，就可以把它作为一个衡量执行`sync`还是`psync`的一个标准`（backlog = offset : 部分同步，backlog < offset 执行全量同步）`。一般为了避免，大规模全量复制，我们都会给一个恰当的值，根据公式`second*write_size_per_second`来估算：其中`second`为从服务器断线后重新连接上主服务器所需的平均时间（以秒计算）；而`write_size_per_second`则是主服务器平均每秒产生的写命令数据量（协议格式的写命令的长度总和）；

- master run id, `master`唯一标示，`slave`连接`master`时会传`runid`，`master`每次重启`runid`都发生变化，当`slave`发现`master`的`runid`变化时都会触发全量复制流程。

### 优缺点

优点：

1. 高可靠性：一方面，采用双机主备架构，能够在主库出现故障时自动进行主备切换，从库提升为主库提供服务，保证服务平稳运行；另一方面，开启数据持久化功能和配置合理的备份策略，能有效的解决数据误操作和数据异常丢失的问题；
2. 读写分离策略：从节点可以扩展主库节点的读能力，有效应对大并发量的读操作。

缺点：

1. 故障恢复复杂，如果没有`RedisHA`系统（需要开发），当主库节点出现故障时，需要手动将一个从节点晋升为主节点，同时需要通知业务方变更配置，并且需要让其它从库节点去复制新主库节点，整个过程需要人为干预，比较繁琐；
2. 主库的写能力受到单机的限制，可以考虑分片；
3. 主库的存储能力受到单机的限制，可以考虑`Pika`；
4. 原生复制的弊端在早期的版本中也会比较突出，如：`Redis`复制中断后，`Slave`会发起`psync`，此时如果同步不成功，则会进行全量同步，主库执行全量备份的同时可能会造成毫秒或秒级的卡顿；又由于`COW`机制，导致极端情况下的主库内存溢出，程序异常退出或宕机；主库节点生成备份文件导致服务器磁盘`IO`和`CPU`（压缩）资源消耗；发送数`GB`大小的备份文件导致服务器出口带宽暴增，阻塞请求，建议升级到最新版本。

## 二、Redis 哨兵 (Redis Sentinel)

### 什么是哨兵

`Redis Sentinel` 是一个分布式架构，其中包含若干个 `Sentinel` 节点和 `Redis` 数据节点，每个 `Sentinel` 节点会对数据节点和其余 `Sentinel` 节点进行监控，当它发现节点不可达时，会对节点做下线标识。如果被标识的是主节点，它还会和其他 `Sentinel` 节点进行“协商”，当大多数 `Sentinel` 节点都认为主节点不可达时，它们会选举出一个 `Sentinel` 节点来完成自动故障转移的工作，同时会将这个变化实时通知给 `Redis` 应用方。整个过程完全是自动的，不需要人工来介入，所以这套方案很有效地解决了 `Redis` 的高可用问题。

Redis 2.8 版开始正式提供名为`Sentinel`的主从切换方案，`Sentinel`用于管理多个`Redis`服务器实例，主要负责三个方面的任务：

1. 监控（`Monitoring`）： `Sentinel` 会不断地检查你的主服务器和从服务器是否运作正常。
2. 提醒（`Notification`）： 当被监控的某个 `Redis` 服务器出现问题时， `Sentinel` 可以通过 `API` 向管理员或者其他应用程序发送通知。
3. 自动故障迁移（`Automatic failover`）： 当一个主服务器不能正常工作时， `Sentinel` 会开始一次自动故障迁移操作， 它会将失效主服务器的其中一个从服务器升级为新的主服务器， 并让失效主服务器的其他从服务器改为复制新的主服务器； 当客户端试图连接失效的主服务器时， 集群也会向客户端返回新主服务器的地址， 使得集群可以使用新主服务器代替失效服务器。

![](../images/sentinel1.jpg)

哨兵(`sentinel`)  是一个分布式系统,你可以在一个架构中运行多个哨兵(`sentinel`)  进程,这些进程使用流言协议(`gossip protocols`)来接收关于`Master`是否下线的信息,并使用投票协议(`agreement protocols`)来决定是否执行自动故障迁移,以及选择哪个`Slave`作为新的`Master`.

每个哨兵(`sentinel`)  会向其它哨兵(`sentinel`)、`master`、`slave`定时发送消息,以确认对方是否”活”着,如果发现对方在指定时间(可配置)内未回应,则暂时认为对方已挂(所谓的”主观认为宕机” `Subjective Down`,简称`sdown`).

若“哨兵群”中的多数`sentinel`,都报告某一`master`没响应,系统才认为该`master`"彻底死亡"(即:客观上的真正`down`机,`Objective Down`,简称`odown`),通过一定的`vote`算法,从剩下的`slave`节点中,选一台提升为`master`,然后自动修改相关配置.

虽然哨兵(`sentinel`)  释出为一个单独的可执行文件  `redis-sentinel` ,但实际上它只是一个运行在特殊模式下的  `Redis`  服务器，你可以在启动一个普通  `Redis`  服务器时通过给定  `--sentinel`  选项来启动哨兵(`sentinel`).

### 基本的故障转移流程

1. 主节点出现故障，此时两个从节点与主节点失去连接，主从复制失败。
   ![](../images/sentinel2.jpg)
2. 每个 `Sentinel` 节点通过定期监控发现主节点出现了故障
   ![](../images/sentinel3.jpg)
3. 多个 `Sentinel` 节点对主节点的故障达成一致会选举出其中一个节点作为领导者负责故障转移。
   ![](../images/sentinel4.jpg)
4. `Sentinel` 领导者节点执行了故障转移，整个过程基本是跟我们手动调整一致的，只不过是自动化完成的。
   ![](../images/sentinel5.jpg)
5. 故障转移后整个 `Redis Sentinel` 的结构,重新选举了新的主节点。
   ![](../images/sentinel6.jpg)

### 注意事项

1. `Sentinel` 节点不应该部署在一台物理“机器”上。
   这里特意强调物理机是因为一台物理机做成了若干虚拟机或者现今比较流行的容器，它们虽然有不同的 `IP` 地址，但实际上它们都是同一台物理机，同一台物理机意味着如果这台机器有什么硬件故障，所有的虚拟机都会受到影响，为了实现 `Sentinel` 节点集合真正的高可用，请勿将 `Sentinel` 节点部署在同一台物理机器上。

2. 部署至少三个且奇数个的 `Sentinel` 节点。

3. 个以上是通过增加 `Sentinel` 节点的个数提高对于故障判定的准确性，因为领导者选举需要至少一半加 1 个节点，奇数个节点可以在满足该条件的基础上节省一个节点。

### 优缺点

优点：

1. `Redis Sentinel`集群部署简单；
2. 能够解决`Redis`主从模式下的高可用切换问题；
3. 很方便实现`Redis`数据节点的线形扩展，轻松突破`Redis`自身单线程瓶颈，可极大满足`Redis`大容量或高性能的业务需求；
4. 可以实现一套`Sentinel`监控一组`Redis`数据节点或多组数据节点。

缺点：

1. 部署相对`Redis`主从模式要复杂一些，原理理解更繁琐；
2. 资源浪费，`Redis`数据节点中`slave`节点作为备份节点不提供服务；
3. `Redis Sentinel`主要是针对`Redis`数据节点中的主节点的高可用切换，对`Redis`的数据节点做失败判定分为主观下线和客观下线两种，对于`Redis`的从节点有对节点做主观下线操作，并不执行故障转移。
4. 不能解决读写分离问题，实现起来相对复杂。

## 三、Redis 集群 （Redis Cluster）

### 什么是 Redis 集群

`Redis` 集群是一个分布式（`distributed`）、容错（`fault-tolerant`）的 `Redis` 实现， 集群可以使用的功能是普通单机 `Redis` 所能使用的功能的一个子集（`subset`）。

`Redis` 集群中不存在中心（`central`）节点或者代理（`proxy`）节点， 集群的其中一个主要设计目标是达到线性可扩展性（`linear scalability`）。

`Redis` 集群提供了一种运行 `Redis` 的方式，其中数据在多个 `Redis` 节点间自动分区。`Redis` 集群还在分区期间提供一定程度的可用性，即在实际情况下能够在某些节点发生故障或无法通信时继续运行。但是，如果发生较大故障（例如，大多数主站不可用时），集群会停止运行。

### 集群的模型

![](../images/redis_cluster1.png)

1. 所有的节点通过服务通道直接相连，各个节点之间通过二进制协议优化传输的速度和带宽。
2. 客户端与节点之间通过 ascii 协议进行通信
3. 客户端与节点直连，不需要中间 Proxy 层。客户端不需要连接集群所有节点，连接集群中任何一个可用节点即可。
4. 尽管这些节点彼此相连，功能相同，但是仍然分为两种节点：master 和 slave。

### 各个节点之间都传递了什么信息

![](../images/redis_cluster2.png)

通过上面的图我们可以知道各个节点之间通过 PING-PONG 机制通信，下面是一段关于 PING-PONG 机制的会话”内容”。

    节点M：PING，嘿，朋友你好吗？我是 XYZ 哈希槽的 master ，配置信息是 FF89X1JK。

    节点N：PONG，我很好朋友，我也是 XYZ 哈希槽的 master ，配置信息是 FF89X1JK。

    节点M：我这里有一些关于我最近收到的其他节点的信息 ，A 节点回复了我的 PING 消息，我认为 A 节点是正常的。B 没有回应我的消息，我猜它现在可能出问题了，但是我需要一些 ACK(Acknowledgement) 消息来确认。

    节点N：我也想给你分享一些关于其它节点的信息，C 和 D 节点在指定的时间内回应了我， 我认为它们都是正常的，但是 B 也没有回应我，我觉得它现在可能已经挂掉了。

每个节点会向集群中的其他节点发送节点状态信息，如果某个节点挂掉停止了服务，那么会执行投票容错机制，关于这个机制，会在下面讲到。

### Hash 槽(slot)

Redis 集群不使用一致的散列，而是一种不同的分片形式，其中每个键在概念上都是我们称之为散列槽的一部分，目的是使数据均匀的存储在诸多节点中。这点类似于 HashMap 中的桶(bucket)。
![](../images/redis_cluster3.png)

Redis 集群中有 16384 个散列槽，为了计算给定密钥的散列槽，Redis 对 key 采用 CRC16 算法，以下是负责将键映射到槽的算法：

    slot = crc16(key) mod NUMER_SLOTS

例如，你可能有 3 个节点，其中一个集群：

节点 A 包含从 0 到 5500 的散列槽。
节点 B 包含从 5501 到 11000 的散列槽。
节点 C 包含 从 11001 到 16383 的散列槽。
Hash 槽可以轻松地添加和删除集群中的节点。例如，如果我想添加一个新节点 D，我需要将节点 A，B，C 中的一些散列槽移动到 D。同样，如果我想从节点 A 中删除节点 A，可以只移动由 A 服务的散列槽到 B 和 C。当节点 A 为空时，可以将它从群集中彻底删除。

![](../images/redis_cluster4.png)

1. 对象保存到 Redis 之前先经过 CRC16 哈希到一个指定的 Node 上，例如 Object4 最终 Hash 到了 Node1 上。

2. 每个 Node 被平均分配了一个 Slot 段，对应着 0-16384，Slot 不能重复也不能缺失，否则会导致对象重复存储或无法存储。

3. Node 之间也互相监听，一旦有 Node 退出或者加入，会按照 Slot 为单位做数据的迁移。例如 Node1 如果掉线了，0-5640 这些 Slot 将会平均分摊到 Node2 和 Node3 上,由于 Node2 和 Node3 本身维护的 Slot 还会在自己身上不会被重新分配，所以迁移过程中不会影响到 5641-16384Slot 段的使用。

![](../images/redis_cluster5.png)

想扩展并发读就添加 Slaver，想扩展并发写就添加 Master，想扩容也就是添加 Master，任何一个 Slaver 或者几个 Master 挂了都不会是灾难性的故障。

简单总结下哈希 Slot 的优缺点：

缺点：每个 Node 承担着互相监听、高并发数据写入、高并发数据读出，工作任务繁重

优点：将 Redis 的写操作分摊到了多个节点上，提高写的并发能力，扩容简单。

### 容错

![](../images/redis_cluster6.png)

- 集群中的节点不断的 `PING` 其他的节点，当一个节点向另一个节点发送 `PING` 命令， 但是目标节点未能在给定的时限内回复， 那么发送命令的节点会将目标节点标记为 `PFAIL`(`possible failure`，可能已失效)。
- 当节点接收到其他节点发来的信息时， 它会记下那些被其他节点标记为失效的节点。 这被称为失效报告（`failure report`）。
- 如果节点已经将某个节点标记为 `PFAIL` ， 并且根据节点所收到的失效报告显式， 集群中的大部分其他主节点也认为那个节点进入了失效状态， 那么节点会将那个失效节点的状态标记为 `FAIL` 。
- 一旦某个节点被标记为 `FAIL` ， 关于这个节点已失效的信息就会被广播到整个集群， 所有接收到这条信息的节点都会将失效节点标记为 `FAIL` 。

简单来说， 一个节点要将另一个节点标记为失效， 必须先询问其他节点的意见， 并且得到大部分主节点的同意才行。

- 如果被标记为 `FAIL` 的是从节点， 那么当这个节点重新上线时， `FAIL` 标记就会被移除。 一个从节点是否处于 `FAIL` 状态， 决定了这个从节点在有需要时能否被提升为主节点。
- 如果一个主节点被打上 `FAIL` 标记之后， 经过了节点超时时限的四倍时间， 再加上十秒钟之后， 针对这个主节点的槽的故障转移操作仍未完成， 并且这个主节点已经重新上线的话， 那么移除对这个节点的 `FAIL` 标记。在不符合上面的条件后，一旦某个主节点进入 `FAIL` 状态， 如果这个主节点有一个或多个从节点存在， 那么其中一个从节点会被升级为新的主节点， 而其他从节点则会开始对这个新的主节点进行复制。

### 优缺点

优点：

1. 无中心架构；
2. 数据按照`slot`存储分布在多个节点，节点间数据共享，可动态调整数据分布；
3. 可扩展性：可线性扩展到 1000 多个节点，节点可动态添加或删除；
4. 高可用性：部分节点不可用时，集群仍可用。通过增加`Slave`做`standby`数据副本，能够实现故障自动`failover`，节点之间通过`gossip`协议交换状态信息，用投票机制完成`Slave`到`Master`的角色提升；
5. 降低运维成本，提高系统的扩展性和可用性。

缺点：

1. `Client`实现复杂，驱动要求实现`Smart Client`，缓存`slots mapping`信息并及时更新，提高了开发难度，客户端的不成熟影响业务的稳定性。目前仅`JedisCluster`相对成熟，异常处理部分还不完善，比如常见的`“max redirect exception”`。
2. 节点会因为某些原因发生阻塞（阻塞时间大于`clutser-node-timeout`），被判断下线，这种`failover`是没有必要的。
3. 数据通过异步复制，不保证数据的强一致性。
4. 多个业务使用同一套集群时，无法根据统计区分冷热数据，资源隔离性较差，容易出现相互影响的情况。
5. `Slave`在集群中充当“冷备”，不能缓解读压力，当然可以通过`SDK`的合理设计来提高`Slave`资源的利用率。
6. `Key`批量操作限制，如使用`mset`、`mget`目前只支持具有相同`slot`值的`Key`执行批量操作。对于映射为不同`slot`值的`Key`由于`Keys`不支持跨`slot`查询，所以执行`mset`、`mget`、`sunion`等操作支持不友好。
7. `Key`事务操作支持有限，只支持多`key`在同一节点上的事务操作，当多个`Key`分布于不同的节点上时无法使用事务功能。
8. `Key`作为数据分区的最小粒度，不能将一个很大的键值对象如`hash`、`list`等映射到不同的节点。
9. 不支持多数据库空间，单机下的`redis`可以支持到 16 个数据库，集群模式下只能使用 1 个数据库空间，即 db 0。
10. 复制结构只支持一层，从节点只能复制主节点，不支持嵌套树状复制结构。
11. 避免产生`hot-key`，导致主库节点成为系统的短板。
12. 避免产生`big-key`，导致网卡撑爆、慢查询等。
13. 重试时间应该大于`cluster-node-time`时间。
14. `Redis Cluster`不建议使用`pipeline`和`multi-keys`操作，减少`max redirect`产生的场景。

## 四、Redis 自研高可用架构

Redis 自研的高可用解决方案，主要体现在配置中心、故障探测和 failover 的处理机制上，通常需要根据企业业务的实际线上环境来定制化。

![](../images/redis_custome1.png)

优点：

- 高可靠性、高可用性；
- 自主可控性高；
- 贴切业务实际需求，可缩性好，兼容性好。

缺点：

- 实现复杂，开发成本高；
- 需要建立配套的周边设施，如监控，域名服务，存储元数据信息的数据库等；
- 维护成本高。

## 五、Redis 代理中间件

### Codis

#### 什么是 Codis

`Codis` 是一个代理中间件，用的是 `GO` 语言开发的，如下图，`Codis` 在系统的位置是这样的。

![](../images/redis_codis0.png)

![](../images/codis1.jpg)

`Codis`分为四个部分，分别是`Codis Proxy` (`codis-proxy`)、`Codis Dashboard` (`codis-config`)、`Codis Redis` (`codis-server`)和`ZooKeeper/Etcd`.
`Codis`就是起着一个中间代理的作用，能够把所有的`Redis`实例当成一个来使用，在客户端操作着`SDK`的时候和操作`Redis`的时候是一样的，没有差别。
因为`Codis`是一个无状态的，所以可以增加多个`Codis`来提升`QPS`,同时也可以起着容灾的作用。

#### Codis 分片原理

在`Codis`中，`Codis`会把所有的`key`分成 1024 个槽，这 1024 个槽对应着的就是`Redis`的集群，这个在`Codis`中是会在内存中维护着这 1024 个槽与`Redis`实例的映射关系。这个槽是可以配置，可以设置成 2048 或者是 4096 个。看你的`Redis`的节点数量有多少，偏多的话，可以设置槽多一些。
`Codis`中`key`的分配算法，先是把`key`进行`CRC32` 后，得到一个 32 位的数字，然后再`hash%1024`后得到一个余数，这个值就是这个`key`对应着的槽，这槽后面对应着的就是`redis`的实例。(可以思考一下，为什么 Codis 很多命令行不支持，例如 KEYS 操作)

> `CRC32`:`CRC`本身是“冗余校验码”的意思，`CRC32`则表示会产生一个`32bit`（8 位十六进制数）的校验值。由于`CRC32`产生校验值时源数据块的每一个`bit`（位）都参与了计算，所以数据块中即使只有一位发生了变化，也会得到不同的`CRC32`值。

    Codis中Key的算法代码如下
    //Codis中Key的算法
    hash = crc32(command.key)
    slot_index = hash % 1024
    redis = slots[slot_index].redis
    redis.do(command)

#### Codis 之间的槽位同步

> 思考一个问题：如果这个 Codis 节点只在自己的内存里面维护着槽位与实例的关系,那么它的槽位信息怎么在多个实例间同步呢？

Codis 把这个工作交给了 ZooKeeper 来管理，当 Codis 的 Codis Dashbord 改变槽位的信息的时候，其他的 Codis 节点会监听到 ZooKeeper 的槽位变化，会及时同步过来。如图：

![](../images/codis2.jpg)

#### Codis 中的扩容

> 思考一个问题：在 Codis 中增加了 Redis 节点后,槽位的信息怎么变化，原来的 key 怎么迁移和分配？如果在扩容的时候，这个时候有新的 key 进来，Codis 的处理策略是怎么样的？

因为`Codis`是一个代理中间件，所以这个当需要扩容`Redis`实例的时候，可以直接增加`redis`节点。在槽位分配的时候，可以手动指定`Codis Dashbord`来为新增的节点来分配特定的槽位。

在`Codis`中实现了自定义的扫描指令`SLOTSSCAN`，可以扫描指定的`slot`下的所有的`key`，将这些`key`迁移到新的`Redis`的节点中(话外语：这个是`Codis`定制化的其中一个好处)。

首先，在迁移的时候，会在原来的`Redis`节点和新的`Redis`里都保存着迁移的槽位信息，在迁移的过程中，如果有`key`打进将要迁移或者正在迁移的旧槽位的时候，这个时候`Codis`的处理机制是，先是将这个`key`强制迁移到新的`Redis`节点中，然后再告诉`Codis`,下次如果有新的`key`的打在这个槽位中的话，那么转发到新的节点。代码策略如下：

    slot_index = crc32(command.key) % 1024
    if slot_index in migrating_slots:
    	do_migrate_key(command.key)  # 强制执行迁移
    	redis = slots[slot_index].new_redis
    else:
    	redis = slots[slot_index].redis
    redis.do(command)

#### 自动均衡策略

面对着上面讲的迁移策略，如果有成千上万个节点新增进来，都需要我们手动去迁移吗？那岂不是得累死啊。当然，`Codis`也是考虑到了这一点，所以提供了自动均衡策略。自动均衡策略是这样的，`Codis` 会在机器空闲的时候，观察`Redis`中的实例对应着的`slot`数，如果不平衡的话就会自动进行迁移。

#### Codis 的牺牲

因为`Codis`在`Redis`的基础上的改造，所以在`Codis`上是不支持事务的，同时也会有一些命令行不支持，在官方的文档上有(`Codis`不支持的命令)
官方的建议是单个集合的总容量不要超过 1M,否则在迁移的时候会有卡顿感。在`Codis`中，增加了`proxy`来当中转层，所以在网络开销上，是会比单个的`Redis`节点的性能有所下降的，所以这部分会有些的性能消耗。可以增加`proxy`的数量来避免掉这块的性能损耗。

#### MGET 的过程

> 思考一个问题：如果熟悉 Redis 中的 MGET、MSET 和 MSETNX 命令的话，就会知道这三个命令都是原子性的命令。但是，为什么 Codis 支持 MGET 和 MSET,却不支持 MSETNX 命令呢？

![](../images/codis3.jpg)

原因如下:

在`Codis`中的`MGET`命令的原理是这样的，先是在`Redis`中的各个实例里获取到符合的`key`，然后再汇总到`Codis`中，如果是`MSETNX`的话，因为`key`可能存在在多个`Redis`的实例中，如果某个实例的设值成功，而另一个实例的设值不成功，从本质上讲这是不成功的，但是分布在多个实例中的`Redis`是没有回滚机制的，所以会产生脏数据，所以 MSETNX 就是不能支持了。

#### Codis 集群总结

- `Codis`是一个代理中间件，通过内存保存着槽位和实例节点之间的映射关系,槽位间的信息同步交给`ZooKeeper`来管理。
- 不支持事务和官方的某些命令，原因就是分布多个的`Redis`实例没有回滚机制和`WAL`,所以是不支持的.

### Twemproxy 代理

#### 什么是 Twemproxy

Twemproxy 也叫 nutcraker。是 Twtter 开源的一个 Redis 和 Memcache 代理服务器，主要用于管理 Redis 和 Memcached 集群，减少与 Cache 服务器直接连接的数量。

![](../images/redis_twemproxy1.png)

基于 twemproxy 的高可用架构图

![](../images/redis_twemproxy2.png)

### Twemproxy 特性

- 轻量级、快速
- 保持长连接
- 减少了直接与缓存服务器连接的连接数量
- 使用 pipelining 处理请求和响应
- 支持代理到多台服务器上
- 同时支持多个服务器池
- 自动分片数据到多个服务器上
- 实现完整的 memcached 的 ASCII 和再分配协议
- 通过 yaml 文件配置服务器池
- 支持多个哈希模式，包括一致性哈希和分布
- 能够配置删除故障节点
- 可以通过端口监控状态
- 支持 linux, \*bsd,os x 和 solaris

## 参考文章

[Redis 主从复制看这篇就够了](http://blog.itpub.net/31545684/viewspace-2213629/)

[（一）redis 主从原理及流程——主从复制](https://blog.csdn.net/zb6340430/article/details/80914681)

[这可能是目前最全的 Redis 高可用技术解决方案总结](https://yq.aliyun.com/articles/626532)

[Redis 哨兵机制](https://segmentfault.com/a/1190000018278099?utm_source=tag-newest)

[redis 如何实现高可用【主从复制、哨兵机制】](https://blog.csdn.net/itcats_cn/article/details/82428716)

[理解 Redis 集群](https://blog.csdn.net/codejas/article/details/79854953)

[三张图秒懂 Redis 集群设计原理](https://blog.csdn.net/yejingtao703/article/details/78484151)

[为什么大厂都喜欢用 Codis 来管理分布式集群？](https://juejin.im/post/5c132b076fb9a04a08218eef)
