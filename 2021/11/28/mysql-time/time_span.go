package main

import (
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"net/url"
	"time"
)

/*

DROP TABLE IF EXISTS `ts_test`;
CREATE TABLE ts_test (
	`id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT 'pk',
	`program_insert_time` varchar(100) COMMENT '代码里面获取的时间字符串，insert 语句用的',
	`time_zone` INT COMMENT '插入的时候当前 session 的 time_zone 设置的是什么',
		`loc` varchar(20) COMMENT '插入这个语句时候，dsn 的 loc',
	`ts` TIMESTAMP(6),
	 PRIMARY KEY (id)
);


*/

type TsTest struct {
	ID                int64  // PK
	TimeZone          int64  // 插入这个语句时候，dsn 的 loc
	Loc               string // 插入这个语句时候，dsn 的 loc
	ProgramInsertTime string
	TS                time.Time
}

type timeZone struct {
	Variable_name, Value string
}

const (
	locShanghai = "Asia/Shanghai"
	locSeoul    = "Asia/Seoul"
)

var loc2TimeUTC = map[string]int64{
	locShanghai: 8, // UTC +8
	locSeoul:    9, // UTC +9
}

func main() {
	insertDatetimeWithTimeZone(loc2TimeUTC[locShanghai], locShanghai)
	insertDatetimeWithTimeZone(loc2TimeUTC[locShanghai], locSeoul)
	insertDatetimeWithTimeZone(loc2TimeUTC[locSeoul], locShanghai)
	insertDatetimeWithTimeZone(loc2TimeUTC[locSeoul], locSeoul)

	selectDatetimeWithTimeZone(loc2TimeUTC[locShanghai], locShanghai)
	selectDatetimeWithTimeZone(loc2TimeUTC[locSeoul], locShanghai)
	selectDatetimeWithTimeZone(loc2TimeUTC[locShanghai], locSeoul)
	selectDatetimeWithTimeZone(loc2TimeUTC[locSeoul], locSeoul)
}

func insertDatetimeWithTimeZone(tzValue int64, loc string) {
	tz := getTimeZoneStr(tzValue)
	dsn := getMySQLDSNStr("", 0, "", "", "", loc, tz)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		println(err)
		return
	}

	db = db.Debug()

	now := time.Now()
	formatNow := now.Format("2006-01-02 15:04:05")
	fmt.Println("go time.now = ", now.UTC().String(), "format = ", formatNow)

	tzRes := timeZone{}
	err = db.Raw("show variables like'time_zone'").Scan(&tzRes).Error
	if err != nil {
		println(err.Error())
		return
	}

	println("timeZone", tzRes.Value, tzRes.Variable_name)

	test := TsTest{ProgramInsertTime: now.UTC().String(), TimeZone: tzValue, TS: now, Loc: loc}
	err = db.Table("ts_test").Create(&test).Error
	if err != nil {
		println(err.Error())
		return
	}
}

func getTimeZoneStr(tzValue int64) string {
	tz := fmt.Sprintf("'+%d:00'", tzValue)
	return tz
}

func selectDatetimeWithTimeZone(tzValue int64, loc string) {
	tz := getTimeZoneStr(tzValue)
	dsn := getMySQLDSNStr("", 0, "", "", "", loc, tz)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		println(err)
		return
	}

	tzRes := timeZone{}
	err = db.Raw("show variables like'time_zone'").Scan(&tzRes).Error
	if err != nil {
		println(err.Error())
		return
	}

	println("timeZone", tzRes.Value, tzRes.Variable_name)

	var dataArr []*TsTest
	err = db.Table("ts_test").Find(&dataArr).Order("id").Error
	if err != nil {
		println(err.Error())
		return
	}

	for _, data := range dataArr {
		readUTC := loc2TimeUTC[loc]
		insertUTC := loc2TimeUTC[data.Loc]

		if data.Loc == loc && data.TimeZone == tzValue && data.ProgramInsertTime != data.TS.UTC().String() {
			fmt.Println("invalidate =====================================")
		}

		fixTime := data.TS.Add(time.Hour * time.Duration(data.TimeZone-tzValue+readUTC-insertUTC))
		if data.ProgramInsertTime != fixTime.UTC().String() {
			fmt.Println("data.ProgramInsertTime != fixTime.UTC().String()")
		}

		fmt.Printf("read_zone = %s , insert_zone = %s , read_loc = %s , insert_loc = %s, p_time = %s, dateTime = %s , fixDateTime = %s \n",
			getTimeZoneStr(tzValue), getTimeZoneStr(data.TimeZone), loc, data.Loc, data.ProgramInsertTime,
			data.TS.UTC().String(), fixTime.UTC().String())
	}
}

func getMySQLDSNStr(host string, port int, user, password, db, loc, tz string) string {
	loc = url.QueryEscape(loc)
	tz = url.QueryEscape(tz)
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=%s&time_zone=%s",
		user, password, host, port, db, loc, tz)
}
