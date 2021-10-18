/*
 * Copyright 2021 hello.bug@foxmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.black.other;

import org.junit.Test;

public class QuickSort {

    @Test
    public void test() {
        int[] array = {4, 2, 6, 3, 7, 8};
        sort(array, 0, array.length - 1);
        for (int i : array) {
            System.out.println(i);
        }
    }

    private void sort(int[] array, int left, int right) {
        if (left >= right) {
            return;
        }
        // 选择一个坑位
        int n = left;
        int t = array[n];
        int l = left, r = right;
        while (l < r) {
            // 从右侧找比坑位小的(r),放到坑位,坑位更新为 r
            while (l < r && array[r] >= t) {
                r--;
            }
            array[n] = array[r];
            n = r;
            // 从左侧找比坑位大的(l),放到坑位,坑位更新为 l
            while (l < r && array[l] <= t) {
                l++;
            }
            array[n] = array[l];
            n = l;
        }
        array[n] = t;
        sort(array, left, l - 1);
        sort(array, l + 1, right);
    }

}

