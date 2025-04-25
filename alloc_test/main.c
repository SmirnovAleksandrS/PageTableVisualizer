#include <stdio.h>
#include <stdlib.h>

int main() {
    __uint64_t size = 15000; // размер массива
    __uint64_t *array = malloc(size * sizeof(__uint64_t)); // выделение памяти
    for (__uint64_t i = 0; i < size; i ++){
        array[i] = i;
    }
    if (array == NULL) {
        printf("Не удалось выделить память.\n");
        return 1;
    }
    
    getchar(); // ожидание ввода


    free(array); // освобождение памяти
    printf("Память очищена. Завершение программы.\n");

    return 0;
}
