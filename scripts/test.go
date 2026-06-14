package main

import "fmt"

func findMaxConsecutiveOnes(nums []int) int {
	consecutive := 0
	tmp := 0
	for i := range nums {
		if nums[i] == 0 {
			if tmp > consecutive {
				consecutive = tmp
			}
			tmp = 0
		} else {
			tmp++
		}
	}
	if tmp > consecutive {
		consecutive = tmp
	}
	return consecutive
}

func main() {
	fmt.Println(findMaxConsecutiveOnes([]int{1, 0, 1, 1, 0, 1}))
}
