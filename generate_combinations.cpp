#include <iostream>
#include <algorithm>
#include <vector>

// a[] : given array of chars
// perm[] : perm[i] is 1 if a[i] is considered, else 0
// index : subscript of perm which is to be 0ed and 1ed
// n     : length of the given input array
// k     : length of the permuted string
void combinate(char a[], int perm[],int index, int n, int k)
{
   static int count = 0;

   if( count == k )
   {
      for(int i=0; i<n; i++)
        if( perm[i]==1)
          printf("%c",a[i]);
      printf("\n");

    } else if( (n-index)>= (k-count) ){

         perm[index]=1;
         count++;
         combinate(a,perm,index+1,n,k);

         perm[index]=0;
         count--;
         combinate(a,perm,index+1,n,k);

   }
}
int main()
{
   char a[] ={'a','b','c','d'};
   int perm[4] = {0};
   combinate(a,perm,0,4,3);

   return 0;
}
