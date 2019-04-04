Mysql索引


## MySQL常见几种索引类型

1. 普通索引，是最基本的索引，它没有任何限制。它有以下几种创建方式：

	（1）直接创建索引
	
		CREATE INDEX index_name ON table(column(length))
	
	（2）修改表结构的方式添加索引
	
		ALTER TABLE table_name ADD INDEX index_name ON (column(length))
	
	（3）创建表的时候同时创建索引
	
		CREATE TABLE `table` (
		    `id` int(11) NOT NULL AUTO_INCREMENT ,
		    `title` char(255) CHARACTER NOT NULL ,
		    `content` text CHARACTER NULL ,
		    `time` int(10) NULL DEFAULT NULL ,
		    PRIMARY KEY (`id`),
		    INDEX index_name (title(length))
		)
	
	（4）删除索引
	
		DROP INDEX index_name ON table

2. 唯一索引，与前面的普通索引类似，不同的就是：索引列的值必须唯一，但允许有空值。如果是组合索引，则列值的组合必须唯一。它有以下几种创建方式：

	（1）创建唯一索引
	
		CREATE UNIQUE INDEX indexName ON table(column(length))
	
	（2）修改表结构
	
		ALTER TABLE table_name ADD UNIQUE indexName ON (column(length))
	
	（3）创建表的时候直接指定
	
		CREATE TABLE `table` (
		    `id` int(11) NOT NULL AUTO_INCREMENT ,
		    `title` char(255) CHARACTER NOT NULL ,
		    `content` text CHARACTER NULL ,
		    `time` int(10) NULL DEFAULT NULL ,
		    UNIQUE indexName (title(length))
		);


3. 主键索引，是一种特殊的唯一索引，一个表只能有一个主键，不允许有空值。
	
	一般是在建表的时候同时创建主键索引：
		
		CREATE TABLE `table` (
		    `id` int(11) NOT NULL AUTO_INCREMENT ,
		    `title` char(255) NOT NULL ,
		    PRIMARY KEY (`id`)
		);


4. 组合索引，指多个字段上创建的索引，只有在查询条件中使用了创建索引时的第一个字段，索引才会被使用。使用组合索引时遵循最左前缀集合
		
		ALTER TABLE `table` ADD INDEX name_city_age (name,city,age); 

5. 全文索引，主要用来查找文本中的关键字，而不是直接与索引中的值相比较。fulltext索引跟其它索引大不相同，它更像是一个搜索引擎，而不是简单的where语句的参数匹配。fulltext索引配合match against操作使用，而不是一般的where语句加like。它可以在create table，alter table ，create index使用，不过目前只有char、varchar，text 列上可以创建全文索引。值得一提的是，在数据量较大时候，现将数据放入一个没有全局索引的表中，然后再用CREATE index创建fulltext索引，要比先为一张表建立fulltext然后再将数据写入的速度快很多。

	（1）创建表的适合添加全文索引
	
		CREATE TABLE `table` (
		    `id` int(11) NOT NULL AUTO_INCREMENT ,
		    `title` char(255) CHARACTER NOT NULL ,
		    `content` text CHARACTER NULL ,
		    `time` int(10) NULL DEFAULT NULL ,
		    PRIMARY KEY (`id`),
		    FULLTEXT (content)
		);

	（2）修改表结构添加全文索引
	
		ALTER TABLE article ADD FULLTEXT index_content(content)
	
	（3）直接创建索引
	
		CREATE FULLTEXT INDEX index_content ON article(content)
	



## MyISAM和InnoDB索引实现


### MyISAM索引实现
MyISAM引擎使用B+Tree作为索引结构，叶节点的data域存放的是数据记录的地址。下图是MyISAM索引的原理图：

![](./images/MyISAM1.png)

这里设表一共有三列，假设我们以Col1为主键，则图8是一个MyISAM表的主索引（Primary key）示意。可以看出MyISAM的索引文件仅仅保存数据记录的地址。在MyISAM中，主索引和辅助索引（Secondary key）在结构上没有任何区别，只是主索引要求key是唯一的，而辅助索引的key可以重复。如果我们在Col2上建立一个辅助索引，则此索引的结构如下图所示：

![](./images/MyISAM2.png)

同样也是一颗B+Tree，data域保存数据记录的地址。因此，MyISAM中索引检索的算法为首先按照B+Tree搜索算法搜索索引，如果指定的Key存在，则取出其data域的值，然后以data域的值为地址，读取相应数据记录。

MyISAM的索引方式也叫做**“非聚集”**的，之所以这么称呼是为了与InnoDB的聚集索引区分。


### InnoDB索引实现

虽然InnoDB也使用B+Tree作为索引结构，但具体实现方式却与MyISAM截然不同。

第一个重大区别是InnoDB的数据文件本身就是索引文件。从上文知道，MyISAM索引文件和数据文件是分离的，索引文件仅保存数据记录的地址。而在InnoDB中，表数据文件本身就是按B+Tree组织的一个索引结构，这棵树的叶节点data域保存了完整的数据记录。这个索引的key是数据表的主键，因此InnoDB表数据文件本身就是主索引。

![](./images/InnoDB1.png)

图10是InnoDB主索引（同时也是数据文件）的示意图，可以看到叶节点包含了完整的数据记录。这种索引叫做聚集索引。因为InnoDB的数据文件本身要按主键聚集，所以InnoDB要求表必须有主键（MyISAM可以没有），如果没有显式指定，则MySQL系统会自动选择一个可以唯一标识数据记录的列作为主键，如果不存在这种列，则MySQL自动为InnoDB表生成一个隐含字段作为主键，这个字段长度为6个字节，类型为长整形。

第二个与MyISAM索引的不同是InnoDB的辅助索引data域存储相应记录主键的值而不是地址。换句话说，InnoDB的所有辅助索引都引用主键作为data域。例如，图11为定义在Col3上的一个辅助索引：

![](./images/InnoDB2.png)


#### Innodb的聚集索引

Innodb的存储索引是基于B+tree，理所当然，聚集索引也是基于B+tree。与非聚集索引的区别则是，聚集索引既存储了索引，也存储了行值。当一个表有一个聚集索引，它的数据是存储在索引的叶子页（leaf pages）。因此innodb也能理解为基于索引的表。

#### Innodb如何选择一个聚集索引
对于Innodb，主键毫无疑问是一个聚集索引。但是当一个表没有主键，或者没有一个索引，Innodb会如何处理呢。请看如下规则

如果一个主键被定义了，那么这个主键就是作为聚集索引

如果没有主键被定义，那么该表的第一个唯一非空索引被作为聚集索引

如果没有主键也没有合适的唯一索引，那么innodb内部会生成一个隐藏的主键作为聚集索引，这个隐藏的主键是一个6个字节的列，改列的值会随着数据的插入自增。

还有一个需要注意的是：

次级索引的叶子节点并不存储行数据的物理地址。而是存储的该行的主键值。

所以：一次级索引包含了两次查找。一次是查找次级索引自身。然后查找主键（聚集索引）

#### 建立自增主键的原因是：
Innodb中的每张表都会有一个聚集索引，而聚集索引又是以物理磁盘顺序来存储的，自增主键会把数据自动向后插入，避免了插入过程中的聚集索引排序问题。聚集索引的排序，必然会带来大范围的数据的物理移动，这里面带来的磁盘IO性能损耗是非常大的。 

而如果聚集索引上的值可以改动的话，那么也会触发物理磁盘上的移动，于是就可能出现page分裂，表碎片横生。

解读中的第二点相信看了上面关于聚集索引的解释后就很清楚了。




### 聚集索引和非聚集索引解释

聚集（clustered）索引，也叫聚簇索引。
> 定义：数据行的物理顺序与列值（一般是主键的那一列）的逻辑顺序相同，一个表中只能拥有一个聚集索引。

![](./images/mysql-index-clustered.jpg)


非聚集（unclustered）索引。
> 定义：该索引中索引的逻辑顺序与磁盘上行的物理存储顺序不同，一个表中可以拥有多个非聚集索引。

![](./images/mysql-index-unclustered.jpg)


非聚集索引查询过程：

![](./images/mysql-index-unclustered2.jpg)


## 索引的缺点
1. 虽然索引大大提高了查询速度，同时却会降低更新表的速度，如对表进行insert、update和delete。因为更新表时，不仅要保存数据，还要保存一下索引文件。
2. 建立索引会占用磁盘空间的索引文件。一般情况这个问题不太严重，但如果你在一个大表上创建了多种组合索引，索引文件的会增长很快。
3. 索引只是提高效率的一个因素，如果有大数据量的表，就需要花时间研究建立最优秀的索引，或优化查询语句。





## 注意事项
使用索引时，有以下一些技巧和注意事项：

1. 索引不会包含有null值的列

	只要列中包含有null值都将不会被包含在索引中，复合索引中只要有一列含有null值，那么这一列对于此复合索引就是无效的。所以我们在数据库设计时不要让字段的默认值为null。

2. 使用短索引

	对串列进行索引，如果可能应该指定一个前缀长度。例如，如果有一个char(255)的列，如果在前10个或20个字符内，多数值是惟一的，那么就不要对整个列进行索引。短索引不仅可以提高查询速度而且可以节省磁盘空间和I/O操作。
3. 索引列排序

	查询只使用一个索引，因此如果where子句中已经使用了索引的话，那么order by中的列是不会使用索引的。因此数据库默认排序可以符合要求的情况下不要使用排序操作；尽量不要包含多个列的排序，如果需要最好给这些列创建复合索引。
4. like语句操作

	一般情况下不推荐使用like操作，如果非使用不可，如何使用也是一个问题。like “%aaa%” 不会使用索引而like “aaa%”可以使用索引。
	
5. 不要在列上进行运算

	这将导致索引失效而进行全表扫描，例如
	
		SELECT * FROM table_name WHERE YEAR(column_name)<2017;
		
6. 不使用not in和<>操作


### SQL索引优化案例分析

假设访问mysql各种访问方式的耗时如下

1. 随机访问耗时：需要寻道、寻扇区、数据传输，平均耗时大约在10ms量级

2. 顺序访问耗时：顺序访问需要数据传输，平均耗时大约在0.01ms量级（根据磁盘的数据传输速率计算）

3. FETCH耗时：获取表记录的耗时，平均耗时按在0.1ms量级算


#### 创建表

	CREATE TABLE `charge_table`(
	   `uid` int(10) UNSIGNED NOT NULL DEFAULT '0' COMMENT 'user id',
		`client_type` TINYINT(3) UNSIGNED NOT NULL DEFAULT '0' COMMENT 'user id',
		`recharge_time` INT(10) UNSIGNED NOT NULL DEFAULT '0' COMMENT 'charge time',
		`recharge_gold` INT(10) UNSIGNED NOT NULL DEFAULT '0' COMMENT 'charge gold',
		PRIMARY KEY (`uid`),
		KEY `rtime` (`recharge_time`)
	)ENGINE=INNODB DEFAULT CHARSET=utf8
	
	
索引分析：

有根据充值时间段查询充值记录的需求，因此在recharge_time上建了索引

但是在uid上建立了主键即uid也是聚集索引，因此数据表按照uid的顺序组织

表按uid聚集，因此recharge_time相邻的数据在表中并不相邻，而是分散在不同地方	
	

执行下面的语句

	select * from charge_table 
	where recharge_time <= unix_timestamp() 
	and recharge_time >= unix_timestamp() - 60 * 60
	order by recharge_time desc
	limit 30;

根据SQL我们可以分析出这条SQL执行的过程如下：

1. 索引访问：

	1次随机访问找到索引上第一条符合条件的索引行
	
	29次顺序访问找到满足条件的剩余29个索引行

2. 表访问：

	30次随机访问找到表上符合条件的表行
	
3. FETCH：

	30次FETCH获取100条记录


本地响应时间 =

 随机访问次数 * 随机访问耗时  + 顺序访问次数 * 顺序访问耗时 + FETCH次数 * FETCH耗时
 
 = 31 * 10ms + 29 * 0.01 + 30 * 0.1 = 313.29ms


**优化方法：增加自增主键id**

**优化原理：将对表的随机访问转为顺序访问**

索引访问：1次随机访问 + 29次顺序访问

表访问：1次随机访问 + 29次顺序访问

FETCH：30次

本地响应时间 =

 随机访问次数 * 随机访问耗时  + 顺序访问次数 * 顺序访问耗时 + FETCH次数 * FETCH耗时

 = 2 * 10ms + 58 * 0.01 + 30 * 0.1 = 23.58ms
 
 
## Explain 
在日常工作中，我们会有时会开慢查询去记录一些执行时间比较久的SQL语句，找出这些SQL语句并不意味着完事了，些时我们常常用到explain这个命令来查看一个这些SQL语句的执行计划，查看该SQL语句有没有使用上了索引，有没有做全表扫描，这都可以通过explain命令来查看。所以我们深入了解MySQL的基于开销的优化器，还可以获得很多可能被优化器考虑到的访问策略的细节，以及当运行SQL语句时哪种策略预计会被优化器采用。（QEP：sql生成一个执行计划query Execution plan）

	mysql> explain select * from servers;


| id | select_type | table   | type | possible_keys | key  | key_len | ref  | rows | Extra |
|----|-------------|---------|------|---------------|------|---------|------|------|-------|
|  1 | SIMPLE      | servers | ALL  | NULL          | NULL | NULL    | NULL |    1 | NULL  |


### Explain 参数解析


一、 id

我的理解是SQL执行的顺序的标识,SQL从大到小的执行

1. id相同时，执行顺序由上至下

2. 如果是子查询，id的序号会递增，id值越大优先级越高，越先被执行

3. id如果相同，可以认为是一组，从上往下顺序执行；在所有组中，id值越大，优先级越高，越先执行



二、select_type

示查询中每个select子句的类型

1. SIMPLE(简单SELECT,不使用UNION或子查询等)

2. PRIMARY(查询中若包含任何复杂的子部分,最外层的select被标记为PRIMARY)

3. UNION(UNION中的第二个或后面的SELECT语句)

4. DEPENDENT UNION(UNION中的第二个或后面的SELECT语句，取决于外面的查询)

5. UNION RESULT(UNION的结果)

6. SUBQUERY(子查询中的第一个SELECT)

7. DEPENDENT SUBQUERY(子查询中的第一个SELECT，取决于外面的查询)

8. DERIVED(派生表的SELECT, FROM子句的子查询)

9. UNCACHEABLE SUBQUERY(一个子查询的结果不能被缓存，必须重新评估外链接的第一行)

 
三、table

显示这一行的数据是关于哪张表的，有时不是真实的表名字,看到的是derivedx(x是个数字,我的理解是第几步执行的结果)
	
	mysql> explain select * from (select * from ( select * from t1 where id=2602) a) b;


| id | select_type | table      | type   | possible_keys     | key     | key_len | ref  | rows | Extra |
|----|-------------|------------|--------|-------------------|---------|---------|------|------|-------|
|  1 | PRIMARY     | <derived2> | system | NULL              | NULL    | NULL    | NULL |    1 |       |
|  2 | DERIVED     | <derived3> | system | NULL              | NULL    | NULL    | NULL |    1 |       |
|  3 | DERIVED     | t1         | const  | PRIMARY,idx_t1_id | PRIMARY | 4       |      |    1 |       |

 

四、type

表示MySQL在表中找到所需行的方式，又称“访问类型”。

常用的类型有： ALL, index,  range, ref, eq_ref, const, system, NULL（从左到右，性能从差到好）

ALL：Full Table Scan， MySQL将遍历全表以找到匹配的行

index: Full Index Scan，index与ALL区别为index类型只遍历索引树

range:只检索给定范围的行，使用一个索引来选择行

ref: 表示上述表的连接匹配条件，即哪些列或常量被用于查找索引列上的值

eq_ref: 类似ref，区别就在使用的索引是唯一索引，对于每个索引键值，表中只有一条记录匹配，简单来说，就是多表连接中使用primary key或者 unique key作为关联条件

const、system: 当MySQL对查询某部分进行优化，并转换为一个常量时，使用这些类型访问。如将主键置于where列表中，MySQL就能将该查询转换为一个常量,system是const类型的特例，当查询的表只有一行的情况下，使用system

NULL: MySQL在优化过程中分解语句，执行时甚至不用访问表或索引，例如从一个索引列里选取最小值可以通过单独索引查找完成。

 

五、possible_keys

指出MySQL能使用哪个索引在表中找到记录，查询涉及到的字段上若存在索引，则该索引将被列出，但不一定被查询使用

该列完全独立于EXPLAIN输出所示的表的次序。这意味着在possible_keys中的某些键实际上不能按生成的表次序使用。
如果该列是NULL，则没有相关的索引。在这种情况下，可以通过检查WHERE子句看是否它引用某些列或适合索引的列来提高你的查询性能。如果是这样，创造一个适当的索引并且再次用EXPLAIN检查查询

 

六、Key

key列显示MySQL实际决定使用的键（索引）

如果没有选择索引，键是NULL。要想强制MySQL使用或忽视possible_keys列中的索引，在查询中使用FORCE INDEX、USE INDEX或者IGNORE INDEX。

 

七、key_len

表示索引中使用的字节数，可通过该列计算查询中使用的索引的长度（key_len显示的值为索引字段的最大可能长度，并非实际使用长度，即key_len是根据表定义计算而得，不是通过表内检索出的）

不损失精确性的情况下，长度越短越好 

 

八、ref

表示上述表的连接匹配条件，即哪些列或常量被用于查找索引列上的值

 

九、rows

 表示MySQL根据表统计信息及索引选用情况，估算的找到所需的记录所需要读取的行数

 

十、Extra

该列包含MySQL解决查询的详细信息,有以下几种情况：

Using where:列数据是从仅仅使用了索引中的信息而没有读取实际的行动的表返回的，这发生在对表的全部的请求列都是同一个索引的部分的时候，表示mysql服务器将在存储引擎检索行后再进行过滤

Using temporary：表示MySQL需要使用临时表来存储结果集，常见于排序和分组查询

Using filesort：MySQL中无法利用索引完成的排序操作称为“文件排序”

Using join buffer：改值强调了在获取连接条件时没有使用索引，并且需要连接缓冲区来存储中间结果。如果出现了这个值，那应该注意，根据查询的具体情况可能需要添加索引来改进能。

Impossible where：这个值强调了where语句会导致没有符合条件的行。

Select tables optimized away：这个值意味着仅通过使用索引，优化器可能仅从聚合函数结果中返回一行

 

总结：

* EXPLAIN不会告诉你关于触发器、存储过程的信息或用户自定义函数对查询的影响情况
* EXPLAIN不考虑各种Cache
* EXPLAIN不能显示MySQL在执行查询时所作的优化工作
* 部分统计信息是估算的，并非精确值
* EXPALIN只能解释SELECT操作，其他操作要重写为SELECT后查看执行计划。

 
 
 
 
## 参考文章


https://blog.csdn.net/alexshi5/article/details/81814772

http://blog.codinglabs.org/articles/theory-of-mysql-index.html

https://www.cnblogs.com/luyucheng/p/6289714.html

https://blog.csdn.net/itguangit/article/details/82145322

https://www.cnblogs.com/xuanzhi201111/p/4175635.html