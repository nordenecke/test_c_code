#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

//test by norden liu!

using namespace std;

enum flag_vector_use{
    TYPE_ELEMENT_AVAILABLE=0,
    TYPE_ELEMENT_INUSE
};
enum search_result{
    DATA_MATCHED=0,
    DATA_NOTFOUND,
    DATA_ERROR
};

#define INTERVAL_CHAR " "//","

int gbacktrace_sum;//current gbacktrace_sum
vector<int> givec;
vector<flag_vector_use> givec_flag;

template <typename T>
struct cmp
{
    bool operator()(const T &x, const T &y)
    {
        return y<x;
    }
};


int str2vec(char str[], vector<int> *ivec)
{
    std::stringstream ss(str);
    int temp;
    while (ss >> temp)
        ivec->push_back(temp);
    return 1;
}

search_result backtrace_search(int element_index,int slot_size, int element_num)
{

    if(gbacktrace_sum>slot_size)//current sum > slot_size
        return DATA_ERROR;
    if(gbacktrace_sum==slot_size)//current sum == slot_size, output result
    {
        for(int j=0;j<element_index;++j)
        {
            if(TYPE_ELEMENT_INUSE == givec_flag[j])
                std::cout<<givec[j]<<" ";
        }
        std::cout<<endl;
        return DATA_MATCHED;
    }
    if(element_index==element_num)//exceed element number
        return DATA_NOTFOUND;
    for(int i=element_index;i<element_num;++i)
    {
        if(givec_flag[i]==TYPE_ELEMENT_AVAILABLE)//available
        {
            givec_flag[i]=TYPE_ELEMENT_INUSE;
            gbacktrace_sum+=givec[i];
            if(DATA_MATCHED == backtrace_search(i+1,slot_size, element_num))
            {
                return DATA_MATCHED;
            }
            givec_flag[i]=TYPE_ELEMENT_AVAILABLE;
            gbacktrace_sum-=givec[i];
            while(i<element_num-1 && givec[i]==givec[i+1])//skip the same value
                i++;
        }
    }
    return DATA_NOTFOUND;
}

int sum_vector(vector< int > ivec)
{
    int total_sum=0;
    for (std::vector<int>::const_iterator i = ivec.begin(); i != ivec.end(); ++i)
        total_sum+=*i;
    return total_sum;
}

void remove_matched_data(void)
{
//    std::cout << std::endl;
//    for(int i=0;i<givec.size();i++)
//        std::cout<<"b givec["<<i<<"]"<<givec[i]<<std::endl;
//    std::cout<<"b givec.size="<<givec.size()<<std::endl;
    if(givec.size()!=givec_flag.size())
    {
        std::cout<<std::endl<<"givec.size()="<<givec.size()<<"givec_flag.size()="<<givec_flag.size()<<std::endl;
        return;
    }
    for(int i=givec_flag.size()-1;i>=0;i--)
    {
        if(TYPE_ELEMENT_INUSE==givec_flag[i])
        {
//            std::cout <<"i=" << i << " givec erase=" << givec[i] << std::endl;
            givec.erase(givec.begin()+i);
        }
    }
//    for(int i=0;i<givec.size();i++)
//        std::cout<<"a givec["<<i<<"]"<<givec[i]<<std::endl;
//    std::cout<<"a givec.size="<<givec.size()<<std::endl;
//
//    for(int i=0;i<givec_flag.size();i++)
//        std::cout<<"b givec_flag["<<i<<"]"<<givec_flag[i]<<std::endl;
//    std::cout<<"b givec_flag.size="<<givec_flag.size()<<std::endl;
    for(int j= givec_flag.size()-1;j>=0;j--)
    {
        if(TYPE_ELEMENT_INUSE==givec_flag[j])
        {
//            std::cout <<"j=" << j << std::endl;
            givec_flag.erase(givec_flag.begin()+j);
        }
    }
//    for(int i=0;i<givec_flag.size();i++)
//        std::cout<<"a givec_flag["<<i<<"]"<<givec_flag[i]<<std::endl;
//    std::cout<<"a givec_flag.size="<<givec_flag.size()<<std::endl;
}

void int2str(const int &int_temp,string &string_temp)
{
        stringstream stream;
        stream<<int_temp;
        string_temp=stream.str();   //also can do stream>>string_temp
}

void str2int(int &int_temp,const string &string_temp)
{
    stringstream stream(string_temp);
    stream>>int_temp;
}

void output_slot_configuration(vector< vector < int> > ivvec, std::ofstream &fout)
{
    if(ivvec.size() == 0)
         return;
    //output to tty
    for (std::vector< vector<int> >::const_iterator it = ivvec.begin(); it != ivvec.end(); ++it)
    {
        if((*it).size()>0)
        {
            std::cout<<"[" ;
            for(int i=0;i<(*it).size(); ++i)
            {
               std::cout<< (*it)[i];
               if(i!=(*it).size()-1)
                   std::cout<<INTERVAL_CHAR;
            }
            std::cout<< "]" ;
        }
        if(it!=ivvec.end()-1)
            std::cout<<INTERVAL_CHAR;
        else
            std::cout<<std::endl;
    }
    //output to CSV
    for (std::vector< vector<int> >::const_iterator it = ivvec.begin(); it != ivvec.end(); ++it)
    {
        if((*it).size()>0)
        {
            for(int i=0;i<(*it).size(); ++i)
            {
               string temp_str;
               int2str((*it)[i],temp_str),
//               std::cout<<"temp_str="<<temp_str;
               fout<<temp_str;
               if(i!=(*it).size()-1)
                   fout<<INTERVAL_CHAR;
            }
//               fout<<INTERVAL_CHAR;
//               fout<< std::endl;
        }

        if(it!=ivvec.end()-1)
            fout<<INTERVAL_CHAR;
//        else
//            fout<<std::endl;

    }
    
}

bool res_slot_allocation(vector<int> ivec, vector<vector <int> > *ivvec, int slot_size, int slot_num)
{//resource re-allocation
    int total_sum=0;
    int cur_slot_size=0;
    search_result ret=DATA_NOTFOUND;
    
    total_sum = sum_vector(givec);
    if(total_sum>slot_size*slot_num)
        return false;
    if(ivec[0]>slot_size)
        return false;
    if(ivec.size()==0||ivec.size()>slot_size*slot_num)
        return false;

//    for(int i=0;i<ivec.size();i++)  //init use flag
//        givec_flag.push_back(TYPE_ELEMENT_AVAILABLE);
//    givec.assign(ivec.begin(),ivec.end());//init current input array
    std::cout<<std::endl;

    cur_slot_size=slot_size;
    while(1)
    {
        ret=backtrace_search(0,cur_slot_size, ivec.size());

        if(DATA_ERROR == ret)
           return false;
        if(DATA_NOTFOUND == ret)
        {
            if(cur_slot_size>0)//search
                cur_slot_size--;
        }
        if(DATA_MATCHED == ret)//put recode into ivvec
        {
            vector<int> temp_ivec;
            for(int j=0;j<givec_flag.size();++j)
            {
                if(TYPE_ELEMENT_INUSE == givec_flag[j])
                {
//                    std::cout<<givec_flag[j]<<INTERVAL_CHAR;
                    temp_ivec.push_back(givec[j]);
                }
            }
            ivvec->push_back(temp_ivec);
            return true;
        }
    }
    return false;
}

int main(int args, char **argv)
{
    std::ifstream fin("sectors.txt", std::ios::in);
    std::ofstream fout_training_sample("sample.csv", std::ios::out);
    std::ofstream fout_configuration_result("configurations.csv", std::ios::out);
    char line[1024]={0};
    int slot_size = 12;
    int slot_num = 4;
    vector<int> ivec;
    vector< vector<int> > ivvec;
    bool ret=false;
    while(fin.getline(line, sizeof(line)))
    {

        slot_size = 12;
        slot_num = 4;
        ivec.clear();
        givec.clear();
        givec_flag.clear();
        gbacktrace_sum=0;
        str2vec(line, &ivec);
        std::cout <<"handle line, ivec size="<< ivec.size()<<" :"<<std::endl;
        for (std::vector<int>::const_iterator i = ivec.begin(); i != ivec.end(); ++i)
            std::cout<< *i << ' ';
        std:sort(ivec.begin(),ivec.end(),cmp<int>());
        std::cout <<std::endl;
        for (std::vector<int>::const_iterator i = ivec.begin(); i != ivec.end(); ++i)
            std::cout<< *i << ' ';
        givec.assign(ivec.begin(),ivec.end());
        for(int i=0;i<givec.size();i++)  //init use flag
            givec_flag.push_back(TYPE_ELEMENT_AVAILABLE);

        ret=res_slot_allocation(givec,&ivvec,slot_size,slot_num); //get first found result;
        if(false==ret)
        {
            std::cout<<"Error sectors config input!" <<std::endl;
        }
        while(--slot_num)//loop for next slot
        {
            remove_matched_data();
            int sum= sum_vector(givec);
            if(sum>slot_size)
            {
                if(false == res_slot_allocation(givec,&ivvec,slot_size,slot_num))
                    std::cout<<"Error sectors config input!" <<std::endl;
            }
            else if((sum<=slot_size)&&(sum!=0))
            {
                ivvec.push_back(givec);
                break;
            }
            else//<0
            {
                break;
            }
        }
        if(true == ret)
        {
            output_slot_configuration(ivvec, fout_configuration_result);
            std::cout<<std::endl;
            fout_configuration_result<<std::endl;
            ivvec.clear();
        }
        std::cout <<std::endl;
    }
    fin.clear();
    fin.close();
    
    fout_training_sample.clear();
    fout_training_sample.close();
    fout_configuration_result.clear();
    fout_configuration_result.close();
    
    return 0;
}
