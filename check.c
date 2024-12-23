#include <stdio.h>

int main(void){
    int counter = 0;
    int outer = 0;
    while(1){
        counter = 0;
        while(1)
        {
            counter ++;
            printf("counter is %d", counter);
            if (counter > 5){
                break;
            }

        }
        if(outer >= 5){
            break;
        }
        outer ++;
    }
}