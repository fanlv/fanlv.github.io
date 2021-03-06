
- [Order by 实现原理](#order-by-实现原理)
	- [全字段排序](#全字段排序)
	- [rowid 排序](#rowid-排序)
- [Join 实现原理](#join-实现原理)
	- [Index Nested-Loop Join - NLJ （无join_buffer）](#index-nested-loop-join---nlj-无join_buffer)
	- [Simple Nested-Loop Join （无join_buffer - mysql 没用）](#simple-nested-loop-join-无join_buffer---mysql-没用)
	- [Block Nested-Loop Join - BNL （有 join_buffer）](#block-nested-loop-join---bnl-有-join_buffer)
		- [BNL 算法的性能问题](#bnl-算法的性能问题)
	- [Multi-Range Read 优化](#multi-range-read-优化)
	- [Batched Key Access - BKA （NLJ - join_buffer）](#batched-key-access---bka-nlj---join_buffer)
		- [临时表去join](#临时表去join)
		- [扩展hash join](#扩展hash-join)
- [临时表](#临时表)
	- [临时表的特点](#临时表的特点)
	- [内存临时表](#内存临时表)
	- [磁盘临时表](#磁盘临时表)
	- [什么时候会使用临时表](#什么时候会使用临时表)
		- [union 执行流程](#union-执行流程)
		- [group by 执行流程](#group-by-执行流程)
		- [group by 优化方法 -- 索引](#group-by-优化方法----索引)
		- [group by 优化方法 -- 直接排序](#group-by-优化方法----直接排序)
		- [distinct 和 group by 的性能](#distinct-和-group-by-的性能)
		- [group by 指导原则](#group-by-指导原则)
- [其他](#其他)
	- [重建表](#重建表)
	- [Online DDL](#online-ddl)
		- [Online 和 inplace](#online-和-inplace)
	- [count(*)、count(主键 id) 和 count(1)](#countcount主键-id-和-count1)
	- [内存表](#内存表)
	- [自增主键为什么不是连续的](#自增主键为什么不是连续的)
	- [慢查询性能问题](#慢查询性能问题)

## Order by 实现原理

### 全字段排序
	

	select city,name,age 
	CREATE TABLE `t` (
	  `id` int(11) NOT NULL,
	  `city` varchar(16) NOT NULL,
	  `name` varchar(16) NOT NULL,
	  `age` int(11) NOT NULL,
	  `addr` varchar(128) DEFAULT NULL,
	  PRIMARY KEY (`id`),
	  KEY `city` (`city`)
	) ENGINE=InnoDB;
	
	select from t where city='杭州' order by name limit 1000  ;


![image.png](https://upload-images.jianshu.io/upload_images/12321605-add9a6a6719df461.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

1. 初始化 sort_buffer，确定放入 name、city、age 这三个字段；
2. 从索引 city 找到第一个满足 city='杭州’条件的主键 id，也就是图中的 ID_X；
3. 到主键 id 索引取出整行，取 name、city、age 三个字段的值，存入 sort_buffer 中；
4. 从索引 city 取下一个记录的主键 id；
5. 重复步骤 3、4 直到 city 的值不满足查询条件为止，对应的主键 id 也就是图中的 ID_Y；
6. 对 sort_buffer 中的数据按照字段 name 做快速排序；按照排序结果取前 1000 行返回给客户端。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-82eda72c93d03354.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

`sort_buffer_size`，就是 MySQL 为排序开辟的内存（sort_buffer）的大小。如果要排序的数据量小于 `sort_buffer_size`，排序就在内存中完成。但如果排序数据量太大，内存放不下，则不得不利用磁盘临时文件辅助排序。

你可以用下面介绍的方法，来确定一个排序语句是否使用了临时文件

	
	/* 打开optimizer_trace，只对本线程有效 */
	SET optimizer_trace='enabled=on'; 
	
	/* @a保存Innodb_rows_read的初始值 */
	select VARIABLE_VALUE into @a from  performance_schema.session_status where variable_name = 'Innodb_rows_read';
	
	/* 执行语句 */
	select city, name,age from t where city='杭州' order by name limit 1000; 
	
	/* 查看 OPTIMIZER_TRACE 输出 */
	SELECT * FROM `information_schema`.`OPTIMIZER_TRACE`\G
	
	/* @b保存Innodb_rows_read的当前值 */
	select VARIABLE_VALUE into @b from performance_schema.session_status where variable_name = 'Innodb_rows_read';
	
	/* 计算Innodb_rows_read差值 */
	select @b-@a;
	
	
这个方法是通过查看 OPTIMIZER_TRACE 的结果来确认的，你可以从 `number_of_tmp_files` 中看到是否使用了临时文件。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-b99aa8b9dfcfbebb.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

`number_of_tmp_files` 表示的是，排序过程中使用的临时文件数。你一定奇怪，为什么需要 12 个文件？内存放不下时，就需要使用外部排序，**外部排序一般使用归并排序算法**。可以这么简单理解，MySQL 将需要排序的数据分成 12 份，每一份单独排序后存在这些临时文件中。然后把这 12 个有序文件再合并成一个有序的大文件。

我们的示例表中有 4000 条满足 city='杭州’的记录，所以你可以看到 examined_rows=4000，表示参与排序的行数是 4000 行。

sort_mode 里面的 packed_additional_fields 的意思是，排序过程对字符串做了“紧凑”处理。即使 name 字段的定义是 varchar(16)，在排序过程中还是要按照实际长度来分配空间的。

同时，最后一个查询语句 select @b-@a 的返回结果是 4000，表示整个执行过程只扫描了 4000 行。



### rowid 排序

如果 MySQL 认为排序的单行长度太大会怎么做呢？

`max_length_for_sort_data`，是 MySQL 中专门控制用于排序的行数据的长度的一个参数。它的意思是，如果单行的长度超过这个值，MySQL 就认为单行太大，要换一个算法。

新的算法放入 sort_buffer 的字段，只有要排序的列（即 name 字段）和主键 id。

1. 始化 sort_buffer，确定放入两个字段，即 name 和 id；
2. 从索引 city 找到第一个满足 city='杭州’条件的主键 id，也就是图中的 ID_X；
3. 到主键 id 索引取出整行，取 name、id 这两个字段，存入 sort_buffer 中；
4. 从索引 city 取下一个记录的主键 id；
5. 重复步骤 3、4 直到不满足 city='杭州’条件为止，也就是图中的 ID_Y；
6. 对 sort_buffer 中的数据按照字段 name 进行排序；
7. 遍历排序结果，取前 1000 行，并按照 id 的值回到原表中取出 city、name 和 age 三个字段返回给客户端。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-378fffb77a7ad391.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


![image.png](https://upload-images.jianshu.io/upload_images/12321605-830abf5d761db5dd.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


现在，我们就来看看结果有什么不同。

* 首先，图中的 examined_rows 的值还是 4000，表示用于排序的数据是 4000 行。但是 select @b-@a 这个语句的值变成 5000 了。
* 因为这时候除了排序过程外，在排序完成后，还要根据 id 去原表取值。由于语句是 limit 1000，因此会多读 1000 行。

从 OPTIMIZER_TRACE 的结果中，你还能看到另外两个信息也变了。

* sort_mode 变成了 ，表示参与排序的只有 name 和 id 这两个字段。
* number_of_tmp_files 变成 10 了，是因为这时候参与排序的行数虽然仍然是 4000 行，但是每一行都变小了，因此需要排序的总数据量就变小了，需要的临时文件也相应地变少了。



## Join 实现原理

	
	CREATE TABLE `t2` (
	  `id` int(11) NOT NULL,
	  `a` int(11) DEFAULT NULL,
	  `b` int(11) DEFAULT NULL,
	  PRIMARY KEY (`id`),
	  KEY `a` (`a`)
	) ENGINE=InnoDB;
	
	drop procedure idata;
	delimiter ;;
	create procedure idata()
	begin
	  declare i int;
	  set i=1;
	  while(i<=1000)do
	    insert into t2 values(i, i, i);
	    set i=i+1;
	  end while;
	end;;
	delimiter ;
	call idata();
	
	create table t1 like t2;
	insert into t1 (select * from t2 where id<=100)

### Index Nested-Loop Join - NLJ （无join_buffer）


	select * from t1 straight_join t2 on (t1.a=t2.a);


如果直接使用 join 语句，MySQL 优化器可能会选择表 t1 或 t2 作为驱动表，这样会影响我们分析 SQL 语句的执行过程。所以，为了便于分析执行过程中的性能问题，我改用 straight_join 让 MySQL 使用固定的连接方式执行查询，这样优化器只会按照我们指定的方式去 join。在这个语句里，t1 是驱动表，t2 是被驱动表。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-c1b57f4a9e0419e6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

可以看到，在这条语句里，被驱动表 t2 的字段 a 上有索引，join 过程用上了这个索引，因此这个语句的执行流程是这样的：

1. 从表 t1 中读入一行数据 R；
2. 从数据行 R 中，取出 a 字段到表 t2 里去查找；
3. 取出表 t2 中满足条件的行，跟 R 组成一行，作为结果集的一部分；
4. 重复执行步骤 1 到 3，直到表 t1 的末尾循环结束。

这个过程是先遍历表 t1，然后根据从表 t1 中取出的每行数据中的 a 值，去表 t2 中查找满足条件的记录。在形式上，这个过程就跟我们写程序时的嵌套查询类似，并且可以用上被驱动表的索引，所以我们称之为“Index Nested-Loop Join”，简称 NLJ。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-9acb602e169b749f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


在这个流程里：

1. 对驱动表 t1 做了全表扫描，这个过程需要扫描 100 行；
2. 而对于每一行 R，根据 a 字段去表 t2 查找，走的是树搜索过程。由于我们构造的数据都是一一对应的，因此每次的搜索过程都只扫描一行，也是总共扫描 100 行；
3. 所以，整个执行流程，总扫描行数是 200。


到这里小结一下，通过上面的分析我们得到了两个结论：

1. 使用 join 语句，性能比强行拆成多个单表执行 SQL 语句的性能要好；
2. 如果使用 join 语句的话，需要让小表做驱动表。

### Simple Nested-Loop Join （无join_buffer - mysql 没用）

	select * from t1 straight_join t2 on (t1.a=t2.b);
	
	
由于表 t2 的字段 b 上没有索引，因此再用图 2 的执行流程时，每次到 t2 去匹配的时候，就要做一次全表扫描。

你可以先设想一下这个问题，继续使用图 2 的算法，是不是可以得到正确的结果呢？如果只看结果的话，这个算法是正确的，而且这个算法也有一个名字，叫做“Simple Nested-Loop Join”。

但是，这样算来，这个 SQL 请求就要扫描表 t2 多达 100 次，总共扫描 100*1000=10 万行。

这还只是两个小表，如果 t1 和 t2 都是 10 万行的表（当然了，这也还是属于小表的范围），就要扫描 100 亿行，这个算法看上去太“笨重”了。

当然**，MySQL 也没有使用这个 Simple Nested-Loop Join 算法**，而是使用了另一个叫作“Block Nested-Loop Join”的算法，简称 BNL。

### Block Nested-Loop Join - BNL （有 join_buffer）

这时候，被驱动表上没有可用的索引，算法的流程是这样的：


1. 把表 t1 的数据读入线程内存 join_buffer 中，由于我们这个语句中写的是 select *，因此是把整个表 t1 放入了内存；
2. 扫描表 t2，把表 t2 中的每一行取出来，跟 join_buffer 中的数据做对比，满足 join 条件的，作为结果集的一部分返回。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-95f132a8113eebab.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


![image.png](https://upload-images.jianshu.io/upload_images/12321605-89b38f61b4f9f067.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

可以看到，在这个过程中，对表 t1 和 t2 都做了一次全表扫描，因此总的扫描行数是 1100。由于 join_buffer 是以无序数组的方式组织的，因此对表 t2 中的每一行，都要做 100 次判断，总共需要在内存中做的判断次数是：100*1000=10 万次。


`join_buffer` 的大小是由参数 `join_buffer_size` 设定的，默认值是 256k。如果放不下表 t1 的所有数据话，策略很简单，就是分段放。我把 `join_buffer_size` 改成 1200，再执行：


	select * from t1 straight_join t2 on (t1.a=t2.b);
	
	
执行过程就变成了：

1. 扫描表 t1，顺序读取数据行放入 join_buffer 中，放完第 88 行 join_buffer 满了，继续第 2 步；
2. 扫描表 t2，把 t2 中的每一行取出来，跟 join_buffer 中的数据做对比，满足 join 条件的，作为结果集的一部分返回；
3. 清空 join_buffer；
4. 继续扫描表 t1，顺序读取最后的 12 行数据放入 join_buffer 中，继续执行第 2 步。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-97a082ef3ba4bb5c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

图中的步骤 4 和 5，表示清空 join_buffer 再复用。

这个流程才体现出了这个算法名字中“Block”的由来，表示“分块去 join”。


可以看到，这时候由于表 t1 被分成了两次放入 join_buffer 中，导致表 t2 会被扫描两次。虽然分成两次放入 join_buffer，但是判断等值条件的次数还是不变的，依然是 (88+12)*1000=10 万次。


第一个问题：能不能使用 join 语句？

1. 如果可以使用 Index Nested-Loop Join 算法，也就是说可以用上被驱动表上的索引，其实是没问题的；
2. 如果使用 Block Nested-Loop Join 算法，扫描行数就会过多。尤其是在大表上的 join 操作，这样可能要扫描被驱动表很多次，会占用大量的系统资源。所以这种 join 尽量不要用。

所以你在判断要不要使用 join 语句时，就是看 explain 结果里面，Extra 字段里面有没有出现“Block Nested Loop”字样。

第二个问题是：如果要使用 join，应该选择大表做驱动表还是选择小表做驱动表？

1. 如果是 Index Nested-Loop Join 算法，应该选择小表做驱动表；
2. 如果是 Block Nested-Loop Join 算法：
    - 在 join_buffer_size 足够大的时候，是一样的；
    - 在 join_buffer_size 不够大的时候（这种情况更常见），应该选择小表做驱动表。

 所以，更准确地说，在决定哪个表做驱动表的时候，应该是两个表按照各自的条件过滤，过滤完成之后，计算参与 join 的各个字段的总数据量，数据量小的那个表，就是“小表”，应该作为驱动表。
 
#### BNL 算法的性能问题

我们说到 InnoDB 的 LRU 算法的时候提到，由于 InnoDB 对 Bufffer Pool 的 LRU 算法做了优化，即：第一次从磁盘读入内存的数据页，会先放在 old 区域。如果 1 秒之后这个数据页不再被访问了，就不会被移动到 LRU 链表头部，这样对 Buffer Pool 的命中率影响就不大。

但是，如果一个使用 BNL 算法的 join 语句，多次扫描一个冷表，而且这个语句执行时间超过 1 秒，就会在再次扫描冷表的时候，把冷表的数据页移到 LRU 链表头部。

这种情况对应的，是冷表的数据量小于整个 Buffer Pool 的 3/8，能够完全放入 old 区域的情况。

如果这个冷表很大，就会出现另外一种情况：业务正常访问的数据页，没有机会进入 young 区域。

由于优化机制的存在，一个正常访问的数据页，要进入 young 区域，需要隔 1 秒后再次被访问到。但是，由于我们的 join 语句在循环读磁盘和淘汰内存页，进入 old 区域的数据页，很可能在 1 秒之内就被淘汰了。这样，就会导致这个 MySQL 实例的 Buffer Pool 在这段时间内，young 区域的数据页没有被合理地淘汰。

也就是说，这两种情况都会影响 Buffer Pool 的正常运作。

大表 join 操作虽然对 IO 有影响，但是在语句执行结束后，对 IO 的影响也就结束了。但是，对 Buffer Pool 的影响就是持续性的，需要依靠后续的查询请求慢慢恢复内存命中率。

也就是说，BNL 算法对系统的影响主要包括三个方面：

1. 可能会多次扫描被驱动表，占用磁盘 IO 资源；
2. 判断 join 条件需要执行 M*N 次对比（M、N 分别是两张表的行数），如果是大表就会占用非常多的 CPU 资源；
3. 可能会导致 Buffer Pool 的热数据被淘汰，影响内存命中率。

### Multi-Range Read 优化 

在介绍 join 语句的优化方案之前，我需要先和你介绍一个知识点，即：Multi-Range Read 优化 (MRR)。这个优化的主要目的是尽量使用顺序读盘。

主键索引是一棵 B+ 树，在这棵树上，每次只能根据一个主键 id 查到一行数据。因此，回表肯定是一行行搜索主键索引的，基本流程如图 1 所示。


![image.png](https://upload-images.jianshu.io/upload_images/12321605-183dd8d210bc98e2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

如果随着 a 的值递增顺序查询的话，**id 的值就变成随机的**，那么就会出现随机访问，性能相对较差。虽然“按行查”这个机制不能改，但是调整查询的顺序，还是能够加速的。


因为大多数的数据都是按照主键递增顺序插入得到的，所以我们可以认为，如果按照主键的递增顺序查询的话，对磁盘的读比较接近顺序读，能够提升读性能。

这就是 MRR 优化的设计思路。此时，语句的执行流程变成了这样：

1. 根据索引 a，定位到满足条件的记录，将 id 值放入 read_rnd_buffer 中 ;
2. 将 read_rnd_buffer 中的 id 进行递增排序；
3. 排序后的 id 数组，依次到主键 id 索引中查记录，并作为结果返回。

这里，read_rnd_buffer 的大小是由 read_rnd_buffer_size 参数控制的。如果步骤 1 中，read_rnd_buffer 放满了，就会先执行完步骤 2 和 3，然后清空 read_rnd_buffer。之后继续找索引 a 的下个记录，并继续循环。

另外需要说明的是，如果你想要稳定地使用 MRR 优化的话，需要设置set optimizer_switch="mrr_cost_based=off"。（官方文档的说法，是现在的优化器策略，判断消耗的时候，会更倾向于不使用 MRR，把 mrr_cost_based 设置为 off，就是固定使用 MRR 了。）

![image.png](https://upload-images.jianshu.io/upload_images/12321605-83dda4dd3e250e4f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![image.png](https://upload-images.jianshu.io/upload_images/12321605-814460f0b60c64c7.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

MRR 能够提升性能的核心在于，这条查询语句在索引 a 上做的是一个范围查询（也就是说，这是一个多值查询），可以得到足够多的主键 id。这样通过排序以后，再去主键索引查数据，才能体现出“顺序性”的优势。

### Batched Key Access - BKA （NLJ - join_buffer）

![image.png](https://upload-images.jianshu.io/upload_images/12321605-af4e048ecf38627d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

NLJ 算法执行的逻辑是：**从驱动表 t1，一行行地取出 a 的值**，再到被驱动表 t2 去做 join。也就是说，对于表 t2 来说，每次都是匹配一个值。这时，MRR 的优势就用不上了。

那怎么才能一次性地多传些值给表 t2 呢？方法就是，从表 t1 里一次性地多拿些行出来，一起传给表 t2。

既然如此，我们就把表 t1 的数据取出来一部分，先放到一个临时内存。这个临时内存不是别人，就是 join_buffer。

通过上一篇文章，我们知道 `join_buffer` 在 BNL 算法里的作用，是暂存驱动表的数据。但是在 NLJ 算法里并没有用。那么，我们刚好就可以复用 `join_buffer` 到 BKA 算法中。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-750b48f0ee00b608.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


#### 临时表去join


	select * from t1 join t2 on (t1.b=t2.b) where t2.b>=1 and t2.b<=2000;

我们在文章开始的时候，在表 t2 中插入了 100 万行数据，但是经过 where 条件过滤后，需要参与 join 的只有 2000 行数据。如果这条语句同时是一个低频的 SQL 语句，那么再为这个语句在表 t2 的字段 b 上创建一个索引就很浪费了。

但是，如果使用 BNL 算法来 join 的话，这个语句的执行流程是这样的：

1. 把表 t1 的所有字段取出来，存入 join_buffer 中。这个表只有 1000 行，join_buffer_size 默认值是 256k，可以完全存入。
2. 扫描表 t2，取出每一行数据跟 join_buffer 中的数据进行对比，
   - 如果不满足 t1.b=t2.b，则跳过；
   - 如果满足 t1.b=t2.b, 再判断其他条件，也就是是否满足 t2.b 处于[1,2000]的条件，如果是，就作为结果集的一部分返回，否则跳过。

 我在上一篇文章中说过，对于表 t2 的每一行，判断 join 是否满足的时候，都需要遍历 join_buffer 中的所有行。因此判断等值条件的次数是 1000*100 万 =10 亿次，这个判断的工作量很大。
 
 ![image.png](https://upload-images.jianshu.io/upload_images/12321605-c93c567cd51dd9c5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/12321605-cd13a7493613b65b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

可以看到，explain 结果里 Extra 字段显示使用了 BNL 算法。在我的测试环境里，这条语句需要执行 1 分 11 秒。


这时候，我们可以考虑使用临时表。使用临时表的大致思路是：

1. 把表 t2 中满足条件的数据放在临时表 tmp_t 中；
2. 为了让 join 使用 BKA 算法，给临时表 tmp_t 的字段 b 加上索引；
3. 让表 t1 和 tmp_t 做 join 操作。

此时，对应的 SQL 语句的写法如下：

	create temporary table temp_t(id int primary key, a int, b int, index(b))engine=innodb;
	insert into temp_t select * from t2 where b>=1 and b<=2000;
	select * from t1 join temp_t on (t1.b=temp_t.b);
	

![image.png](https://upload-images.jianshu.io/upload_images/12321605-c7ab0399b824b793.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


1. 执行 insert 语句构造 temp_t 表并插入数据的过程中，对表 t2 做了全表扫描，这里扫描行数是 100 万。
2. 之后的 join 语句，扫描表 t1，这里的扫描行数是 1000；join 比较过程中，做了 1000 次带索引的查询。相比于优化前的 join 语句需要做 10 亿次条件判断来说，这个优化效果还是很明显的。

#### 扩展hash join

看到这里你可能发现了，其实上面计算 10 亿次那个操作，看上去有点儿傻。如果 join_buffer 里面维护的不是一个无序数组，而是一个哈希表的话，那么就不是 10 亿次判断，而是 100 万次 hash 查找。这样的话，整条语句的执行速度就快多了吧？

这，也正是 MySQL 的优化器和执行器一直被诟病的一个原因：不支持哈希 join。并且，MySQL 官方的 roadmap，也是迟迟没有把这个优化排上议程。

实际上，这个优化思路，我们可以自己实现在业务端。实现流程大致如下：

1. select * from t1;取得表 t1 的全部 1000 行数据，在业务端存入一个 hash 结构，比如 C++ 里的 set、PHP 的数组这样的数据结构。
2. select * from t2 where b>=1 and b<=2000; 获取表 t2 中满足条件的 2000 行数据。
3. 把这 2000 行数据，一行一行地取到业务端，到 hash 结构的数据表中寻找匹配的数据。满足匹配的条件的这行数据，就作为结果集的一行。


## 临时表

### 临时表的特点

1. 建表语法是 create temporary table …。
2. 一个临时表只能被创建它的 session 访问，对其他线程不可见。所以，图中 session A 创建的临时表 t，对于 session B 就是不可见的。
3. 临时表可以与普通表同名。
4. session A 内有同名的临时表和普通表的时候，show create 语句，以及增删改查语句访问的是临时表。session A 内有同名的临时表和普通表的时候，show create 语句，以及增删改查语句访问的是临时表。
5. show tables 命令不显示临时表。

由于临时表只能被创建它的 session 访问，所以在这个 session 结束的时候，会自动删除临时表。也正是由于这个特性，临时表就特别适合我们文章开头的 join 优化这种场景。为什么呢？

原因主要包括以下两个方面：

1. 不同 session 的临时表是可以重名的，如果有多个 session 同时执行 join 优化，不需要担心表名重复导致建表失败的问题。
2. 不需要担心数据删除问题。如果使用普通表，在流程执行过程中客户端发生了异常断开，或者数据库发生异常重启，还需要专门来清理中间过程中生成的数据表。而临时表由于会自动回收，所以不需要这个额外的操作。

### 内存临时表
	
	
	mysql> CREATE TABLE `words` (
	  `id` int(11) NOT NULL AUTO_INCREMENT,
	  `word` varchar(64) DEFAULT NULL,
	  PRIMARY KEY (`id`)
	) ENGINE=InnoDB;
	
	delimiter ;;
	create procedure idata()
	begin
	  declare i int;
	  set i=0;
	  while i<10000 do
	    insert into words(word) values(concat(char(97+(i div 1000)), char(97+(i % 1000 div 100)), char(97+(i % 100 div 10)), char(97+(i % 10))));
	    set i=i+1;
	  end while;
	end;;
	delimiter ;
	
	call idata();
	
这个语句的意思很直白，随机排序取前 3 个。虽然这个 SQL 语句写法很简单，但执行流程却有点复杂的。

	mysql> select word from words order by rand() limit 3;
	
我们先用 explain 命令来看看这个语句的执行情况。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-19f40953fafe8881.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

1. 创建一个临时表。这个临时表使用的是 memory 引擎，表里有两个字段，第一个字段是 double 类型，为了后面描述方便，记为字段 R，第二个字段是 varchar(64) 类型，记为字段 W。并且，这个表没有建索引。
2. 从 words 表中，按主键顺序取出所有的 word 值。对于每一个 word 值，调用 rand() 函数生成一个大于 0 小于 1 的随机小数，并把这个随机小数和 word 分别存入临时表的 R 和 W 字段中，到此，扫描行数是 10000。
3. 现在临时表有 10000 行数据了，接下来你要在这个没有索引的内存临时表上，按照字段 R 排序。
4. 初始化 sort_buffer。sort_buffer 中有两个字段，一个是 double 类型，另一个是整型。
5. 从内存临时表中一行一行地取出 R 值和位置信息（我后面会和你解释这里为什么是“位置信息”），分别存入 sort_buffer 中的两个字段里。这个过程要对内存临时表做全表扫描，此时扫描行数增加 10000，变成了 20000。
6. 在 sort_buffer 中根据 R 的值进行排序。注意，这个过程没有涉及到表操作，所以不会增加扫描行数。
7. 排序完成后，取出前三个结果的位置信息，依次到内存临时表中取出 word 值，返回给客户端。这个过程中，访问了表的三行数据，总扫描行数变成了 20003。


![image.png](https://upload-images.jianshu.io/upload_images/12321605-184b04aae91a1b8f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


### 磁盘临时表

其实不是的。tmp_table_size 这个配置限制了内存临时表的大小，默认值是 16M。如果临时表大小超过了 tmp_table_size，那么内存临时表就会转成磁盘临时表。

磁盘临时表使用的引擎默认是 InnoDB，是由参数 internal_tmp_disk_storage_engine 控制的。


	set tmp_table_size=1024;
	set sort_buffer_size=32768;
	set max_length_for_sort_data=16;
	/* 打开 optimizer_trace，只对本线程有效 */
	SET optimizer_trace='enabled=on'; 
	
	/* 执行语句 */
	select word from words order by rand() limit 3;
	
	/* 查看 OPTIMIZER_TRACE 输出 */
	SELECT * FROM `information_schema`.`OPTIMIZER_TRACE`\G

![image.png](https://upload-images.jianshu.io/upload_images/12321605-1b6eb162e47ef602.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


因为将 max_length_for_sort_data 设置成 16，小于 word 字段的长度定义，所以我们看到 sort_mode 里面显示的是 rowid 排序，这个是符合预期的，参与排序的是随机值 R 字段和 rowid 字段组成的行。


这个 SQL 语句的排序确实没有用到临时文件，采用是 MySQL 5.6 版本引入的一个新的排序算法，即：优先队列排序算法。接下来，我们就看看为什么没有使用临时文件的算法，也就是归并排序算法，而是采用了优先队列排序算法。

这个 SQL 语句的排序确实没有用到临时文件，采用是 MySQL 5.6 版本引入的一个新的排序算法，即：优先队列排序算法。接下来，我们就看看为什么没有使用临时文件的算法，也就是归并排序算法，而是采用了优先队列排序算法。

其实，我们现在的 SQL 语句，只需要取 R 值最小的 3 个 rowid。但是，如果使用归并排序算法的话，虽然最终也能得到前 3 个值，但是这个算法结束后，已经将 10000 行数据都排好序了。

图 5 的 OPTIMIZER_TRACE 结果中，filesort_priority_queue_optimization 这个部分的 chosen=true，就表示使用了优先队列排序算法，这个过程不需要临时文件，因此对应的 number_of_tmp_files 是 0。

你可能会问，这里也用到了 limit，为什么没用优先队列排序算法呢？原因是，这条 SQL 语句是 limit 1000，如果使用优先队列算法的话，需要维护的堆的大小就是 1000 行的 (name,rowid)，超过了我设置的 sort_buffer_size 大小，所以只能使用归并排序算法。


###  什么时候会使用临时表

#### union 执行流程


	create table t1(id int primary key, a int, b int, index(a));
	delimiter ;;
	create procedure idata()
	begin
	  declare i int;
	
	  set i=1;
	  while(i<=1000)do
	    insert into t1 values(i, i, i);
	    set i=i+1;
	  end while;
	end;;
	delimiter ;
	call idata();

然后，我们执行下面这条语句：

	(select 1000 as f) union (select id from t1 order by id desc limit 2);
	
这条语句用到了 union，它的语义是，取这两个子查询结果的并集。并集的意思就是这两个集合加起来，重复的行只保留一行。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-4001801f06638ca4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

* 第二行的 key=PRIMARY，说明第二个子句用到了索引 id。
* 第三行的 Extra 字段，表示在对子查询的结果集做 union 的时候，使用了临时表 (Using temporary)。


这个语句的执行流程是这样的：

1. 创建一个内存临时表，这个临时表只有一个整型字段 f，并且 f 是主键字段。
2. 执行第一个子查询，得到 1000 这个值，并存入临时表中。
3. 执行第二个子查询：
	- 拿到第一行 id=1000，试图插入临时表中。但由于 1000 这个值已经存在于临时表了，违反了唯一性约束，所以插入失败，然后继续执行；
	- 取到第二行 id=999，插入临时表成功。
4. 从临时表中按行取出数据，返回结果，并删除临时表，结果中包含两行数据分别是 1000 和 999。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-27a0ebaf024b74ae.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


#### group by 执行流程

	select id%10 as m, count(*) as c from t1 group by m;
	
	
	
这个语句的逻辑是把表 t1 里的数据，按照 id%10 进行分组统计，并按照 m 的结果排序后输出。它的 explain 结果如下：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-35b19794e6c2f1db.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

在 Extra 字段里面，我们可以看到三个信息：

* Using index，表示这个语句使用了覆盖索引，选择了索引 a，不需要回表；
* Using temporary，表示使用了临时表；
* Using filesort，表示需要排序。


这个语句的执行流程是这样的：

1. 创建内存临时表，表里有两个字段 m 和 c，主键是 m；
2. 扫描表 t1 的索引 a，依次取出叶子节点上的 id 值，计算 id%10 的结果，记为 x；
	- 如果临时表中没有主键为 x 的行，就插入一个记录 (x,1);
	- 如果表中有主键为 x 的行，就将 x 这一行的 c 值加 1；
3. 遍历完成后，再根据字段 m 做排序，得到结果集返回给客户端。


这个流程的执行图如下：

![image.png](https://upload-images.jianshu.io/upload_images/12321605-638c0dea792883ae.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

图中最后一步，对内存临时表的排序，在第 17 篇文章中已经有过介绍，我把图贴过来，方便你回顾。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-edd24def2b9c5a44.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

如果你的需求并不需要对结果进行排序，那你可以在 SQL 语句末尾增加 order by null，也就是改成：如果你的需求并不需要对结果进行排序，那你可以在 SQL 语句末尾增加 order by null，也就是改成：

	select id%10 as m, count(*) as c from t1 group by m order by null;
	
把内存临时表的大小限制为最大 1024 字节，并把语句改成 id % 100，这样返回结果里有 100 行数据。但是，这时的内存临时表大小不够存下这 100 行数据，也就是说，执行过程中会发现内存临时表大小到达了上限（1024 字节）。

那么，这时候就会把内存临时表转成磁盘临时表，磁盘临时表默认使用的引擎是 InnoDB。 这时，返回的结果如图 9 所示。

如果这个表 t1 的数据量很大，很可能这个查询需要的磁盘临时表就会占用大量的磁盘空间。

#### group by 优化方法 -- 索引

在 MySQL 5.7 版本支持了 generated column 机制，用来实现列数据的关联更新。你可以用下面的方法创建一个列 z，然后在 z 列上创建一个索引（如果是 MySQL 5.6 及之前的版本，你也可以创建普通列和索引，来解决这个问题）。

	alter table t1 add column z int generated always as(id % 100), add index(z);

这样，索引 z 上的数据就是类似图 10 这样有序的了。上面的 group by 语句就可以改成：

	select z, count(*) as c from t1 group by z;
	
#### group by 优化方法 -- 直接排序

所以，如果可以通过加索引来完成 group by 逻辑就再好不过了。但是，如果碰上不适合创建索引的场景，我们还是要老老实实做排序的。那么，这时候的 group by 要怎么优化呢？

如果我们明明知道，一个 group by 语句中需要放到临时表上的数据量特别大，却还是要按照“先放到内存临时表，插入一部分数据后，发现内存临时表不够用了再转成磁盘临时表”，看上去就有点儿傻。

那么，我们就会想了，MySQL 有没有让我们直接走磁盘临时表的方法呢？

在 group by 语句中加入 SQL_BIG_RESULT 这个提示（hint），就可以告诉优化器：这个语句涉及的数据量很大，请直接用磁盘临时表。

MySQL 的优化器一看，磁盘临时表是 B+ 树存储，存储效率不如数组来得高。所以，既然你告诉我数据量很大，那从磁盘空间考虑，还是直接用数组来存吧。

	select SQL_BIG_RESULT id%100 as m, count(*) as c from t1 group by m;
	
的执行流程就是这样的：

1. 初始化 sort_buffer，确定放入一个整型字段，记为 m；
2. 扫描表 t1 的索引 a，依次取出里面的 id 值, 将 id%100 的值存入 sort_buffer 中；
3. 扫描完成后，对 sort_buffer 的字段 m 做排序（如果 sort_buffer 内存不够用，就会利用磁盘临时文件辅助排序）；
4. 排序完成后，就得到了一个有序数组。


![image.png](https://upload-images.jianshu.io/upload_images/12321605-ae7d42d638c79aa1.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

![image.png](https://upload-images.jianshu.io/upload_images/12321605-394d69bd71231348.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

从 Extra 字段可以看到，这个语句的执行没有再使用临时表，而是直接用了排序算法。


基于上面的 union、union all 和 group by 语句的执行过程的分析，我们来回答文章开头的问题：MySQL 什么时候会使用内部临时表？


1. 如果语句执行过程可以一边读数据，一边直接得到结果，是不需要额外内存的，否则就需要额外的内存，来保存中间结果；
2. join_buffer 是无序数组，sort_buffer 是有序数组，临时表是二维表结构；
3. 如果执行逻辑需要用到二维表特性，就会优先考虑使用临时表。比如我们的例子中，union 需要用到唯一索引约束， group by 还需要用到另外一个字段来存累积计数。

#### distinct 和 group by 的性能

	select a from t group by a order by null;
	select distinct a from t;
	
首先需要说明的是，这种 group by 的写法，并不是 SQL 标准的写法。标准的 group by 语句，是需要在 select 部分加一个聚合函数，比如：

	select a,count(*) from t group by a order by null;

这条语句的逻辑是：按照字段 a 分组，计算每组的 a 出现的次数。在这个结果里，由于做的是聚合计算，相同的 a 只出现一次。

没有了 count(*) 以后，也就是不再需要执行“计算总数”的逻辑时，第一条语句的逻辑就变成是：按照字段 a 做分组，相同的 a 的值只返回一行。而这就是 distinct 的语义，所以不需要执行聚合函数时，distinct 和 group by 这两条语句的语义和执行流程是相同的，因此执行性能也相同。

这两条语句的执行流程是下面这样的。


#### group by 指导原则

1. 如果对 group by 语句的结果没有排序要求，要在语句后面加 order by null；
2. 尽量让 group by 过程用上表的索引，确认方法是 explain 结果里没有 Using temporary 和 Using filesort；
3. 如果 group by 需要统计的数据量不大，尽量只使用内存临时表；也可以通过适当调大 tmp_table_size 参数，来避免用到磁盘临时表；
4. 如果数据量实在太大，使用 SQL_BIG_RESULT 这个提示，来告诉优化器直接使用排序算法得到 group by 的结果。


## 其他

###  重建表

试想一下，如果你现在有一个表 A，需要做空间收缩，为了把表中存在的空洞去掉，你可以怎么做呢？

你可以新建一个与表 A 结构相同的表 B，然后按照主键 ID 递增的顺序，把数据一行一行地从表 A 里读出来再插入到表 B 中。

这里，你可以使用 alter table A engine=InnoDB 命令来重建表。在 MySQL 5.5 版本之前，这个命令的执行流程跟我们前面描述的差不多，区别只是这个临时表 B 不需要你自己创建，MySQL 会自动完成转存数据、交换表名、删除旧表的操作。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-2a6bac61608d54ee.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

###  Online DDL

1. 建立一个临时文件，扫描表 A 主键的所有数据页；
2. 用数据页中表 A 的记录生成 B+ 树，存储到临时文件中；
3. 生成临时文件的过程中，将所有对 A 的操作记录在一个日志文件（row log）中，对应的是图中 state2 的状态；
4. 临时文件生成后，将日志文件中的操作应用到临时文件，得到一个逻辑数据上与表 A 相同的数据文件，对应的就是图中 state3 的状态；
5. 用临时文件替换表 A 的数据文件。

![image.png](https://upload-images.jianshu.io/upload_images/12321605-79ff4f42f79adfce.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

确实，图 4 的流程中，alter 语句在启动的时候需要获取 MDL 写锁，但是这个写锁在真正拷贝数据之前就退化成读锁了。


为什么要退化呢？为了实现 Online，MDL 读锁不会阻塞增删改操作。

那为什么不干脆直接解锁呢？为了保护自己，禁止其他线程对这个表同时做 DDL。

而对于一个大表来说，Online DDL 最耗时的过程就是拷贝数据到临时表的过程，这个步骤的执行期间可以接受增删改操作。所以，相对于整个 DDL 过程来说，锁的时间非常短。对业务来说，就可以认为是 Online 的。

另一种典型的大事务场景，就是大表 DDL。这个场景,处理方案就是，计划内的 DDL，建议使用 gh-ost 方案。

#### Online 和 inplace

如果说这两个逻辑之间的关系是什么的话，可以概括为：

1. DDL 过程如果是 Online 的，就一定是 inplace 的；
2. 反过来未必，也就是说 inplace 的 DDL，有可能不是 Online 的。截止到 MySQL 8.0，添加全文索引（FULLTEXT index）和空间索引 (SPATIAL index) 就属于这种情况。

有同学问到使用 optimize table、analyze table 和 alter table 这三种方式重建表的区别。
这里，我顺便再简单和你解释一下。

* 从 MySQL 5.6 版本开始，alter table t engine = InnoDB（也就是 recreate）默认的就是上面图 4 的流程了；
* analyze table t 其实不是重建表，只是对表的索引信息做重新统计，没有修改数据，这个过程中加了 MDL 读锁；
* optimize table t 等于 recreate+analyze。


### count(*)、count(主键 id) 和 count(1)

对于 count(主键 id) 来说，InnoDB 引擎会遍历整张表，把每一行的 id 值都取出来，返回给 server 层。server 层拿到 id 后，判断是不可能为空的，就按行累加。

对于 count(1) 来说，InnoDB 引擎遍历整张表，但不取值。server 层对于返回的每一行，放一个数字“1”进去，判断是不可能为空的，按行累加。


对于 count(字段) 来说： 

1. 如果这个“字段”是定义为 not null 的话，一行行地从记录里面读出这个字段，判断不能为 null，按行累加；
2. 如果这个“字段”定义允许为 null，那么执行的时候，判断到有可能是 null，还要把值取出来再判断一下，不是 null 才累加。


但是 `count(*)` 是例外，并不会把全部字段取出来，而是专门做了优化，不取值。count(*) 肯定不是 null，按行累加。

所以结论是：按照效率排序的话，count(字段)< count(主键 id) < count(1) ≈count(*)，所以我建议你，尽量使用 count(*)。

### 内存表

可见，InnoDB 和 Memory 引擎的数据组织方式是不同的：

* InnoDB 引擎把数据放在主键索引上，其他索引上保存的是主键 id。这种方式，我们称之为索引组织表（Index Organizied Table）。
* 而 Memory 引擎采用的是把数据单独存放，索引上保存数据位置的数据组织形式，我们称之为堆组织表（Heap Organizied Table）。

从中我们可以看出，这两个引擎的一些典型不同：

1. InnoDB 表的数据总是有序存放的，而内存表的数据就是按照写入顺序存放的；
2. 当数据文件有空洞的时候，InnoDB 表在插入新数据的时候，为了保证数据有序性，只能在固定的位置写入新值，而内存表找到空位就可以插入新值；
3. 数据位置发生变化的时候，InnoDB 表只需要修改主键索引，而内存表需要修改所有索引；
4. InnoDB 表用主键索引查询时需要走一次索引查找，用普通索引查询的时候，需要走两次索引查找。而内存表没有这个区别，所有索引的“地位”都是相同的。
5. InnoDB 支持变长数据类型，不同记录的长度可能不同；内存表不支持 Blob 和 Text 字段，并且即使定义了 varchar(N)，实际也当作 char(N)，也就是固定长度字符串来存储，因此内存表的每行数据长度相同。
6. 内存表不支持行锁，只支持表锁。因此，一张表只要有更新，就会堵住其他所有在这个表上的读写操作。
7. 数据放在内存中，是内存表的优势，但也是一个劣势。因为，数据库重启的时候，所有的内存表都会被清空。

由于内存表的这些特性，每个数据行被删除以后，空出的这个位置都可以被接下来要插入的数据复用。比如，如果要在表 t1 中执行：

基于内存表的特性，我们还分析了它的一个适用场景，就是内存临时表。内存表支持 hash 索引，这个特性利用起来，对复杂查询的加速效果还是很不错的。


### 自增主键为什么不是连续的

MySQL 5.1.22 版本引入了一个新策略，新增参数 innodb_autoinc_lock_mode，默认值是 1。

* 这个参数的值被设置为 0 时，表示采用之前 MySQL 5.0 版本的策略，即语句执行结束后才释放锁；
* 这个参数的值被设置为 1 时：
	- 普通 insert 语句，自增锁在申请之后就马上释放；
	- 类似 insert … select 这样的批量插入数据的语句，自增锁还是要等语句结束后才被释放.
* 这个参数的值被设置为 2 时，所有的申请自增主键的动作都是申请后就释放锁。



在 MySQL 5.7 及之前的版本，自增值保存在内存里，并没有持久化。每次重启后，第一次打开表的时候，都会去找自增值的最大值 max(id)，然后将 max(id)+1 作为这个表当前的自增值。﻿

在 MyISAM 引擎里面，自增值是被写在数据文件上的。而在 InnoDB 中，自增值是被记录在内存的。MySQL 直到 8.0 版本，才给 InnoDB 表的自增值加上了持久化的能力，确保重启前后一个表的自增值不变。

MySQL 5.1.22 版本开始引入的参数 innodb_autoinc_lock_mode，控制了自增值申请时的锁范围。从并发性能的角度考虑，我建议你将其设置为 2，同时将 binlog_format 设置为 row。我在前面的文章中其实多次提到，binlog_format 设置为 row，是很有必要的。今天的例子给这个结论多了一个理由。


在什么场景下自增主键可能不连续

1：唯一键冲突
2：事务回滚
3：自增主键的批量申请

深层次原因是，不判断自增主键是否已存在可减少加锁的时间范围和粒度->为了更高的性能->自增主键不能回退->自增主键不连续

###  慢查询性能问题

1. 索引没有设计好；
2. SQL 语句没写好；
3. MySQL 选错了索引。