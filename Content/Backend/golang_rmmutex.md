# Golang RWMutext 代码走读

	type RWMutex struct {
	   w           Mutex  // held if there are pending writers
	   writerSem   uint32 // 写的信号量
	   readerSem   uint32 // 读的信号量
	   readerCount int32  // 等待写的个数
	   readerWait  int32  // 等待读的个数
	}
	
	// 加“读锁”
	// 对readerCount + 1 。
	// 然后看 readerCount是不是小于0
	// 小于0表示 正在加写锁，然后阻塞到rw.readerSem 这个信号上。
	func (rw *RWMutex) RLock() {
	   if atomic.AddInt32(&rw.readerCount, 1) < 0 {
	      // A writer is pending, wait for it.
	      runtime_SemacquireMutex(&rw.readerSem, false, 0)
	   }
	}
	
	// 释放 “读锁”
	// 对readerCount - 1 。
	// 然后看 readerCount是不是小于0
	// 小于0表示 正在加写锁，然后调用rw.rUnlockSlow
	func (rw *RWMutex) RUnlock() {
	   if r := atomic.AddInt32(&rw.readerCount, -1); r < 0 {
	      // Outlined slow-path to allow the fast-path to be inlined
	      rw.rUnlockSlow(r)
	   }
	}
	
	// r+1 == -rwmutexMaxReaders 表示“读锁”已经释放，抛出异常
	// rw.readerWait - 1 
	// rw.readerWait - 1 = 0 表示所有读锁都释放了
	// 所有读锁都释放了可以唤醒 rw.writerSem 对应 写锁的lock方法继续执行
	func (rw *RWMutex) rUnlockSlow(r int32) {
	   if r+1 == 0 || r+1 == -rwmutexMaxReaders {
	      race.Enable()
	      throw("sync: RUnlock of unlocked RWMutex")
	   }
	   // A writer is pending.
	   if atomic.AddInt32(&rw.readerWait, -1) == 0 {
	      // The last reader unblocks the writer.
	      runtime_Semrelease(&rw.writerSem, false, 1)
	   }
	}
	// mutex 加锁，保证写锁和写锁之间互斥
	// rw.readerCount - rwmutexMaxReaders
	// r 表示读锁数量
	// rw.readerWait + 读lock的数量 
	// 等待 rw.writerSem 的信号 （读锁那边释放完了，会发这个信号）
	
	func (rw *RWMutex) Lock() {
	   // First, resolve competition with other writers.
	   rw.w.Lock()
	   // Announce to readers there is a pending writer.
	   r := atomic.AddInt32(&rw.readerCount, -rwmutexMaxReaders) + rwmutexMaxReaders
	   // Wait for active readers.
	   if r != 0 && atomic.AddInt32(&rw.readerWait, r) != 0 {
	      runtime_SemacquireMutex(&rw.writerSem, false, 0)
	   }
	}
	// rw.readerCount + rwmutexMaxReaders
	// r 表示读锁的数量，大于 rwmutexMaxReaders 就抛出异常
	// 发送 rw.readerSem  信号量，通知RLock 代码可以继续执行。
	func (rw *RWMutex) Unlock() {
	   // Announce to readers there is no active writer.
	   r := atomic.AddInt32(&rw.readerCount, rwmutexMaxReaders)
	   if r >= rwmutexMaxReaders {
	      race.Enable()
	      throw("sync: Unlock of unlocked RWMutex")
	   }
	   // Unblock blocked readers, if any.
	   for i := 0; i < int(r); i++ {
	      runtime_Semrelease(&rw.readerSem, false, 0)
	   }
