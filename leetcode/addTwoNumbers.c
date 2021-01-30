#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

struct ListNode {
	int val;
	struct ListNode *next;
};

typedef struct ListNode *node;
node addNode(node head, int value);
node createNode();

struct ListNode* addTwoNumbers(struct ListNode* l1, struct ListNode* l2){
    int sum,rem,one,two; sum=rem=0;
    struct ListNode* answer = malloc(sizeof(struct ListNode));
    struct ListNode* temp = answer;  
    
    while(l1 || l2) {
      	if (l1) {one = l1->val;} else {one = 0;} 
      	if (l2) {two = l2->val;} else {two = 0;} 
		sum = one + two + rem;
        if (sum >= 10) { rem = sum/10;} else { rem = 0;}
        sum %= 10;
        temp->val = sum;
        if (l1 = l1) {l1 = l1->next;} else {l1 = NULL;}
        if (l2 = l2) {l2 = l2->next;} else {l2 = NULL;}
        if(l1 || l2) {
            temp->next = malloc(sizeof(struct ListNode));
            temp = temp->next;    
        }
        else if(rem) {
            temp->next = malloc(sizeof(struct ListNode));
            temp = temp->next;
            temp->val = rem;
        }
    }
    temp->next = NULL;
    
    return answer;
}

struct ListNode* addTwoNumbers4(struct ListNode* l1, struct ListNode* l2){
    int sum,rem; sum=rem=0;
    struct ListNode* answer = malloc(sizeof(struct ListNode));
    struct ListNode* temp = answer;  
    
    while(l1 || l2) {
        sum = rem + (l1? l1->val: 0) + (l2? l2->val: 0);
        rem = sum>=10? sum/10: 0;
        sum %= 10;
        temp->val = sum;
        l1 = l1? l1->next: NULL;
        l2 = l2? l2->next: NULL;
        if(l1 || l2) {
            temp->next = malloc(sizeof(struct ListNode));
            temp = temp->next;    
        }
        else if(rem) {
            temp->next = malloc(sizeof(struct ListNode));
            temp = temp->next;
            temp->val = rem;
        }
    }
    temp->next = NULL;
    
    return answer;
}


struct ListNode* addTwoNumbers3(struct ListNode* l1, struct ListNode* l2){
	int sum,tot,rem,one,two;
	char l1v,l2v;
	l1v=l2v='f'; //keep track of whether there is a val to eval
	sum=tot=rem=one=two=0;
	struct ListNode* answer = (struct ListNode*)malloc(sizeof(struct ListNode));

    while(l1!=NULL||l2!=NULL||rem>0)
    {
//		if (l1v != 't') { one = l1->val; } else { one = 0; }
//		if (l2v != 't') { two = l2->val; } else { two = 0; }

		printf("MAIN LOOP l1=%d | l2=%d\n", one, two);
		if (rem == 1) 
		{ 
			printf("ADDING with REM: %d + %d +%d\n", one, two, rem);
			tot=(one)+(two)+rem; 
			rem=0;
		}
 		else { tot = one + two; printf("TOT = %d\n", tot); }
		sum+=tot%10;
		rem+=tot/10;
		struct ListNode* temp = (struct ListNode*)malloc(sizeof(struct ListNode));
		temp->val = sum;
		printf("ADD %d to answer\n", sum); 
 		answer->next = temp;
		if (l1 != NULL) {l1=l1->next;} 
		if (l1 == NULL) {l1v='t';} 
		if (l2 != NULL) {l2=l2->next;} 
		if (l2 == NULL) {l2v='t';} 
    }
    return answer;
}

void main(){
	node l1 = createNode();
    node l2 = createNode();
	addNode(l1, 2);addNode(l1, 4);addNode(l1, 3);
	addNode(l2, 5);addNode(l2, 6);addNode(l2, 7);
	printf("[main] l1 = 2, 4, 3 | l2 = 5, 6, 7\n");	
	node R1 = addTwoNumbers(l1, l2);
	while (R1) {printf("%d", R1->val); R1 = R1->next;}
	printf("\n");
}

node createNode(){
    node temp; // declare a node
    temp = (node)malloc(sizeof(struct ListNode)); // allocate memory using malloc()
    temp->next = NULL;// make next point to NULL
    return temp;//return the new node
}

node addNode(node head, int value){
    node temp,p;// declare two nodes temp and p
    temp = createNode();//createNode will return a new node with data = value and next pointing to NULL.
    temp->val = value; // add element's value to data part of node
    if(head == NULL){
        head = temp;     //when linked list is empty
    }
    else{
        if (head->val == 0){
			head->val = value;
		}
		else {
			p = head; //assign head to p 
	        while(p->next != NULL){
	            p = p->next;//traverse the list until p is the last node.The last node always points to NULL.
	        }
	        p->next = temp;//Point the previous last node to the new node created.
		}
    }
    return head;
}
