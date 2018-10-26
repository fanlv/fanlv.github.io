# MySql存储引擎MyISAM和InnoDB

### 什么是MyISAM 和InnoDB
> MyISAM是MySQL的默认数据库引擎（5.5版之前），由早期的ISAM所改良。虽然性能极佳，但却有一个缺点：不支持事务处理（transaction）。
> 
> InnoDB，是MySQL的数据库引擎之一，为MySQL AB发行binary的标准之一。InnoDB由Innobase Oy公司所开发，2006年五月时由甲骨文公司并购。与传统的ISAM与MyISAM相比，InnoDB的最大特色就是支持了ACID兼容的事务（Transaction）功能，类似于PostgreSQL。

MyISAM：它是基于传统的ISAM类型，ISAM是Indexed Sequential Access Method (有索引的顺序访问方法) 的缩写，它是存储记录和文件的标准方法。不是事务安全的，而且不支持外键，如果执行大量的select，insert MyISAM比较适合。

InnoDB：支持事务安全的引擎，支持外键、行锁、事务是他的最大特点。如果有大量的update和insert，建议使用InnoDB，特别是针对多个并发和QPS较高的情况。



### MyISAM与InnoDB的主要区别:

1. 存储结构

	MyISAM：每个MyISAM在磁盘上存储成三个文件。1）.frm 用于存储表的定义。2）.MYD 用于存放数据。 3）.MYI 用于存放表索引
	
	InnoDB：所有的表都保存在同一个数据文件中（也可能是多个文件，或者是独立的表空间文件），InnoDB表的大小只受限于操作系统文件的大小，一般为2GB。

2. 存储空间

	MyISAM：可被压缩，存储空间较小。支持三种不同的存储格式：静态表(默认，但是注意数据末尾不能有空格，会被去掉)、动态表、压缩表。
	
	InnoDB：需要更多的内存和存储，它会在主内存中建立其专用的缓冲池用于高速缓冲数据和索引。

3. 可移植性、备份及恢复

	MyISAM：数据是以文件的形式存储，所以在跨平台的数据转移中会很方便。在备份和恢复时可单独针对某个表进行操作。
	
	InnoDB：免费的方案可以是拷贝数据文件、备份 binlog，或者用 mysqldump，在数据量达到几十G的时候就相对痛苦了。

4. 事务支持

	MyISAM：强调的是性能，每次查询具有原子性,其执行数度比InnoDB类型更快，但是不提供事务支持。
	InnoDB：提供事务支持事务，外部键等高级数据库功能。 具有事务(commit)、回滚(rollback)和崩溃修复能力(crash recovery capabilities)的事务安全(transaction-safe (ACID compliant))型表。

5. AUTO_INCREMENT

	MyISAM：可以和其他字段一起建立联合索引。引擎的自动增长列必须是索引，如果是组合索引，自动增长可以不是第一列，他可以根据前面几列进行排序后递增。
	InnoDB：InnoDB中必须包含只有该字段的索引。引擎的自动增长列必须是索引，如果是组合索引也必须是组合索引的第一列。

6. 表锁差异

	MyISAM：只支持表级锁，用户在操作myisam表时，select，update，delete，insert语句都会给表自动加锁，如果加锁以后的表满足insert并发的情况下，可以在表的尾部插入新的数据。
	
	InnoDB：
	1. 支持事务和行级锁，是innodb的最大特色。行锁大幅度提高了多用户并发操作的新能。但是InnoDB的行锁，只是在WHERE的主键是有效的，非主键的WHERE都会锁全表的。
	2. 事务的ACID属性：atomicity,consistent,isolation,durable。
	3. 并发事务带来的几个问题：更新丢失，脏读，不可重复读，幻读。
	4. 事务隔离级别：未提交读(Read uncommitted)，已提交读(Read committed)，可重复读(Repeatable read)，可序列化(Serializable)

	|读数据一致性及并发副作用 | 读数据一致性 | 脏读 |不可重复读 |幻读|
	|:------------- |:-------------:| -----:| ----:| --------:|
	|为提交读(read uncommitted)	|最低级别，不读物理上顺坏的数据|是|是|是|
	|已提交读(read committed)	|语句级|否|是|是
	|可重复读(Repeatable red)	|事务级|否|否|是
	|可序列化(Serializable)	|最高级别，事务级|否|否|否


7. 全文索引

	MyISAM：支持 FULLTEXT类型的全文索引
	InnoDB：不支持FULLTEXT类型的全文索引，但是innodb可以使用sphinx插件支持全文索引，并且效果更好。

8. 表主键

	MyISAM：允许没有任何索引和主键的表存在，索引都是保存行的地址。
	InnoDB：如果没有设定主键或者非空唯一索引，就会自动生成一个6字节的主键(用户不可见)，数据是主索引的一部分，附加索引保存的是主索引的值。

9. 表的具体行数

	MyISAM：保存有表的总行数，如果select count( * ) from table;会直接取出出该值。
	InnoDB：没有保存表的总行数，如果使用select count( * ) from table；就会遍历整个表，消耗相当大，但是在加了wehre条件后，myisam和innodb处理的方式都一样。

10. CURD操作

	MyISAM：如果执行大量的SELECT，MyISAM是更好的选择。
	InnoDB：如果你的数据执行大量的INSERT或UPDATE，出于性能方面的考虑，应该使用InnoDB表。DELETE 从性能上InnoDB更优，但DELETE FROM table时，InnoDB不会重新建立表，而是一行一行的删除，在innodb上如果要清空保存有大量数据的表，最好使用truncate table这个命令。

11. 外键

	MyISAM：不支持
	InnoDB：支持
	通过上述的分析，基本上可以考虑使用InnoDB来替代MyISAM引擎了，原因是InnoDB自身很多良好的特点，比如事务支持、存储 过程、视图、行级锁定等等，在并发很多的情况下，相信InnoDB的表现肯定要比MyISAM强很多。另外，任何一种表都不是万能的，只用恰当的针对业务类型来选择合适的表类型，才能最大的发挥MySQL的性能优势。如果不是很复杂的Web应用，非关键应用，还是可以继续考虑MyISAM的，这个具体情况可以自己斟酌。


### 应用场景：
1. MyISAM管理非事务表。它提供高速存储和检索，以及全文搜索能力。如果应用中需要执行大量的SELECT查询，那么MyISAM是更好的选择。
2. InnoDB用于事务处理应用程序，具有众多特性，包括ACID事务支持。如果应用中需要执行大量的INSERT或UPDATE操作，则应该使用InnoDB，这样可以提高多用户并发操作的性能。


### 开发的注意事项

1. 可以用 show create table tablename 命令看表的引擎类型。

2. 对不支持事务的表做start/commit操作没有任何效果，在执行commit前已经提交。

3. 可以执行以下命令来切换非事务表到事务（数据不会丢失），innodb表比myisam表更安全：alter table tablename type=innodb;或者使用 alter table tablename engine = innodb;

4. 默认innodb是开启自动提交的，如果你按照myisam的使用方法来编写代码页不会存在错误，只是性能会很低。如何在编写代码时候提高数据库性能呢？

5. 尽量将多个语句绑到一个事务中，进行提交，避免多次提交导致的数据库开销。

6. 在一个事务获得排他锁或者意向排他锁以后，如果后面还有需要处理的sql语句，在这两条或者多条sql语句之间程序应尽量少的进行逻辑运算和处理，减少锁的时间。

7. 尽量避免死锁

8. sql语句如果有where子句一定要使用索引，尽量避免获取意向排他锁。

9. 针对我们自己的数据库环境，日志系统是直插入，不修改的，所以我们使用混合引擎方式，ZION_LOG_DB照旧使用myisam存储引擎，只有ZION_GAME_DB，ZION_LOGIN_DB，DAUM_BILLING使用Innodb引擎。




## 参考资料

https://blog.csdn.net/wjtlht928/article/details/46641865

https://blog.csdn.net/perfectsorrow/article/details/80150672

http://www.hao124.net/article/111

https://blog.csdn.net/aaa123524457/article/details/54375341