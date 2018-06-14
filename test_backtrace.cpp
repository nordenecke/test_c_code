#include<iostream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>



using namespace std;
int a[100]={6,4,4,4,3,3};
bool x[100];//标记第i个元素是否已经使用
int N=6;//元素个数
int t=12;//目标和
int sum;//当前和
int cmp(const void *a,const void *b)
{
    return *(int *)b-*(int *)a;
}
void backtrace(int n)
{
    if(sum>t)//当前和大于t
        return ;
    if(sum==t)//当前和等于t,输出结果
    {
        for(int j=0;j<n;++j)
        {
            if(x[j])
                cout<<a[j]<<" ";
        }
        cout<<endl;
        return;
    }
    if(n==N)//超过n层
        return ;
    for(int i=n;i<N;++i)
    {
        if(x[i]==false)//未使用
        {
            x[i]=true;
            sum+=a[i];
            backtrace(i+1);
            x[i]=false;
            sum-=a[i];
            while(i<N-1 && a[i]==a[i+1])//跳过相同的
                i++;
        }
    }
}
int main()
{
    sum=0;
    memset(x,0,sizeof(x));
    qsort(a,N,sizeof(a[0]),cmp);
    backtrace(0);
    return 0;
}
