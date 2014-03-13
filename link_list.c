#include<stdio.h>

struct node{
     int i;
     struct node* link;
};

struct node* head = NULL;

void main()
{
   struct node* temp=NULL;
   int counter = 0;
   while(1){
       temp=(struct node*)malloc(sizeof(struct node));
       temp->link = head;
       temp->i = counter++;
       printf("%d\n",temp->i);
       head = temp;
       sleep(1);
   }
   temp = head;
   while (temp){
        printf("%d\n",temp->i);
        temp=temp->link;
   }

}
   
