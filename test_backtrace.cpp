#include<iostream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>



using namespace std;
int a[100]={6,4,4,4,3,3};
bool x[100];//��ǵ�i��Ԫ���Ƿ��Ѿ�ʹ��
int N=6;//Ԫ�ظ���
int t=12;//Ŀ���
int sum;//��ǰ��
int cmp(const void *a,const void *b)
{
    return *(int *)b-*(int *)a;
}
void backtrace(int n)
{
    if(sum>t)//��ǰ�ʹ���t
        return ;
    if(sum==t)//��ǰ�͵���t,������
    {
        for(int j=0;j<n;++j)
        {
            if(x[j])
                cout<<a[j]<<" ";
        }
        cout<<endl;
        return;
    }
    if(n==N)//����n��
        return ;
    for(int i=n;i<N;++i)
    {
        if(x[i]==false)//δʹ��
        {
            x[i]=true;
            sum+=a[i];
            backtrace(i+1);
            x[i]=false;
            sum-=a[i];
            while(i<N-1 && a[i]==a[i+1])//������ͬ��
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
