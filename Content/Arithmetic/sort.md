# 常用的排序算法

- [常用的排序算法](#%e5%b8%b8%e7%94%a8%e7%9a%84%e6%8e%92%e5%ba%8f%e7%ae%97%e6%b3%95)
	- [插入排序](#%e6%8f%92%e5%85%a5%e6%8e%92%e5%ba%8f)
	- [折半插入排序](#%e6%8a%98%e5%8d%8a%e6%8f%92%e5%85%a5%e6%8e%92%e5%ba%8f)
	- [shell 排序](#shell-%e6%8e%92%e5%ba%8f)
	- [冒泡排序](#%e5%86%92%e6%b3%a1%e6%8e%92%e5%ba%8f)
	- [选择排序](#%e9%80%89%e6%8b%a9%e6%8e%92%e5%ba%8f)
	- [快速排序](#%e5%bf%ab%e9%80%9f%e6%8e%92%e5%ba%8f)
	- [基数排序](#%e5%9f%ba%e6%95%b0%e6%8e%92%e5%ba%8f)
	- [归并排序](#%e5%bd%92%e5%b9%b6%e6%8e%92%e5%ba%8f)
	- [堆排序](#%e5%a0%86%e6%8e%92%e5%ba%8f)
	- [KMP查找子串](#kmp%e6%9f%a5%e6%89%be%e5%ad%90%e4%b8%b2)

## 插入排序

	func insertSort(nums []int) {
		for i := 1; i < len(nums); i++ {
			tmp := nums[i]
			for j := i; j >= 0; j-- {
				if j > 0 && tmp < nums[j-1] {
					nums[j] = nums[j-1]
				} else {
					nums[j] = tmp
					break
				}
			}
		}
	}
	

## 折半插入排序

	func binaryInsertSort(nums []int) {
		for i := 1; i < len(nums); i++ {
			left, right := 0, i-1
			mid := 0
			for left < right {
				mid = (left + right) >> 1
				if nums[mid] > nums[i] {
					right = mid - 1
				} else {
					left = mid + 1
				}
			}
			index := right
			tmp := nums[i]
			if nums[right] < tmp {
				index++
			}
			for j := i; j >= index+1; j-- {
				nums[j] = nums[j-1]
			}
			nums[index] = tmp
	
		}
	}
		
## shell 排序
	func shellSort(nums []int) {
		n := len(nums)
		if n == 0 {
			return
		}
	
		for gap := n / 2; gap > 0; gap = gap / 2 {
			for i := gap; i < n; i++ {
				for j := i - gap; j >= 0 && nums[j] > nums[j+gap]; j -= gap {
					nums[j], nums[j+gap] = nums[j+gap], nums[j]
				}
			}
		}
	}

## 冒泡排序

	func bubbleSort(nums []int) {
		for i := 0; i < len(nums); i++ {
			for j := len(nums) - 1; j > i; j-- {
				if nums[j] < nums[j-1] {
					nums[j], nums[j-1] = nums[j-1], nums[j]
				}
			}
		}
	}


## 选择排序
	
	func selectSort(a []int) {
		for i := 0; i < len(a); i++ {
			minIndex := i
			for j := i + 1; j < len(a); j++ {
				if a[minIndex] > a[j] {
					minIndex = j
				}
			}
			a[i], a[minIndex] = a[minIndex], a[i]
		}
	}
	

## 快速排序

	
	func quickSort(arr []int) {
		if len(arr) <= 1 {
			return
		}
		idx := partition(arr)
		quickSort(arr[:idx])
		quickSort(arr[idx+1:])
	}
	
	func partition(a []int) int {
		left := 0
		right := len(a) - 1
		flag := 0
		for left < right {
			for left < right && a[right] >= a[flag] {
				right--
			}
			for left < right && a[left] <= a[flag] {
				left++
			}
			a[left], a[right] = a[right], a[left]
		}
		a[flag], a[right] = a[right], a[flag]
		return right
	}
	
## 基数排序
	
	func radixSort(a []int) {
		n := len(a)
		lists := make([][]int, 10)
		max := a[0]
		for i := 1; i < len(a); i++ {
			if max < a[i] {
				max = a[i]
			}
		}
	
		exp := 1
		for max > 0 {
			//将之前的元素清空
			for i := 0; i < 10; i++ {
				lists[i] = []int{}
			}
			for i := 0; i < n; i++ {
				index := a[i] / exp % 10
				array := lists[index]
				array = append(array, a[i])
				lists[index] = array
			}
			index := 0
			for i := 0; i < 10; i++ {
				arr := lists[i]
				for j := 0; j < len(arr); j++ {
					a[index] = arr[j]
					index++
				}
			}
			max /= 10
			exp *= 10
		}
	}

## 归并排序

	
	func mergeSort(nums []int) []int {
		if len(nums) <= 1 {
			return nums
		}
		left, right := 0, len(nums)
		mid := (left + right) >> 1
		return merge(mergeSort(nums[:mid]), mergeSort(nums[mid:]))
	
	}
	func merge(left, right []int) []int {
		res := make([]int, 0, len(left)+len(right))
		leftIndex := 0
		rightIndex := 0
		for leftIndex < len(left) || rightIndex < len(right) {
			if leftIndex < len(left) && rightIndex < len(right) {
				if left[leftIndex] < right[rightIndex] {
					res = append(res, left[leftIndex])
					leftIndex++
				} else {
					res = append(res, right[rightIndex])
					rightIndex++
				}
			} else if leftIndex == len(left) && rightIndex < len(right) {
				res = append(res, right[rightIndex])
				rightIndex++
			} else if rightIndex == len(right) && leftIndex < len(left) {
				res = append(res, left[leftIndex])
				leftIndex++
			}
		}
		return res
	}

## 堆排序
	
	
	func heapSort(a []int) {
		//构建大顶堆
		lenA := len(a)
		for i := len(a)/2 - 1; i >= 0; i-- {
			adjustHead(a, i, lenA)
		}
		for i := len(a) - 1; i > 0; i-- {
			a[0], a[i] = a[i], a[0]
			adjustHead(a, 0, i)
		}
	
	}
	func adjustHead(a []int, i, length int) {
		tmp := a[i]
		//用k := 2*i + 1 的到i子节点的位置
		for k := 2*i + 1; k < length; k = 2*k + 1 {
			// 让k先指向子节点中最大的节点
			if k+1 < length && a[k] < a[k+1] {
				k++
			}
			if a[k] > tmp { //子节点比根节点大
				a[i], a[k] = a[k], a[i]
				i = k
			} else {
				break
			}
		}
	}


## KMP查找子串
	
	func kmp(str string, needle string) int {
		next := makeNext(str)
		j := 0
		for i := 0; i < len(str); i++ {
			for j > 0 && str[i] != needle[j] {
				j = next[j-1]
			}
			if str[i] == needle[j] {
				j++
			}
			if j == len(needle) {
				return i - j + 1
			}
		}
		return -1
	}
	
	func makeNext(s string) []int {
		next := make([]int, len(s))
		next[0] = 0
		k := 0
		for i := 1; i < len(s); i++ {
			for k > 0 && s[k] != s[i] {
				k = next[k-1]
			}
			if s[k] == s[i] {
				k++
			}
			next[i] = k
		}
		return next
	}