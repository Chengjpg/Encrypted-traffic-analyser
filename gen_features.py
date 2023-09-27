#encoding=UTF-8
import time,os,sys,json
import numpy as np
import pandas as pd
LOCAL_IP_ADDRESS='10.0.2.15' #local host ip address

def gen_flow(filename):
    f_dic= {}
    f_dic['tcp']={}
    f_dic['udp']={}
    with open(filename, 'r', encoding = 'utf-8') as f:
        for line in f:
            line=line.split(",")
            try:
                timestamp=float(line[1])
            except Exception as e:
                break
            proto=line[2]
            ip_src=line[3]
            ip_dst=line[4]
            ip_len=int(line[9])
            direction='->'
            if proto=='6':
                if ip_src==LOCAL_IP_ADDRESS:
                    port_client=line[5]
                    port_server=line[6]
                    direction='->'
                else:
                    port_client=line[6]
                    port_server=line[5]
                    direction='<-'
                key=port_client+'<->'+port_server
                if key not in f_dic['tcp'].keys():
                    f_dic['tcp'][key]={}
                    f_dic['tcp'][key]['->']=[]
                    f_dic['tcp'][key]['<-']=[]
                    f_dic['tcp'][key]['<->']=[]
                    f_dic['tcp'][key][direction].append(ip_len)
                    f_dic['tcp'][key]['time']={}
                    f_dic['tcp'][key]['time'][direction]=[timestamp,0]
                    f_dic['tcp'][key]['time']['<->']=[timestamp,0]
                else:
                    if direction not in f_dic['tcp'][key]['time'].keys():
                        f_dic['tcp'][key]['time'][direction]=[timestamp,0]
                    f_dic['tcp'][key][direction].append(ip_len)
                    f_dic['tcp'][key]['time'][direction][1]=timestamp-f_dic['tcp'][key]['time'][direction][0]
                f_dic['tcp'][key]['<->'].append(ip_len)
                f_dic['tcp'][key]['time']['<->'][1]=timestamp-f_dic['tcp'][key]['time']['<->'][0]
            else:
                if ip_src==LOCAL_IP_ADDRESS:
                    port_client=line[7]
                    port_server=line[8]
                    direction='->'
                else:
                    port_client=line[8]
                    port_server=line[7]
                    direction='<-'
                key=port_client+'<->'+port_server
                if key not in f_dic['udp'].keys():
                    f_dic['udp'][key]={}
                    f_dic['udp'][key]['->']=[]
                    f_dic['udp'][key]['<-']=[]
                    f_dic['udp'][key]['<->']=[]
                    f_dic['udp'][key][direction].append(ip_len)
                    f_dic['udp'][key]['time']={}
                    f_dic['udp'][key]['time'][direction]=[timestamp,0]
                    f_dic['udp'][key]['time']['<->']=[timestamp,0]
                else:
                    if direction not in f_dic['udp'][key]['time'].keys():
                        f_dic['udp'][key]['time'][direction]=[timestamp,0]
                    f_dic['udp'][key][direction].append(ip_len)
                    f_dic['udp'][key]['time'][direction][1]=timestamp-f_dic['udp'][key]['time'][direction][0]
                f_dic['udp'][key]['<->'].append(ip_len)
                f_dic['udp'][key]['time']['<->'][1]=timestamp-f_dic['udp'][key]['time']['<->'][0]
        return f_dic

def get_statistical_fraturs(list,duration):
    f_max=max(list)
    f_min=min(list)
    f_mean=np.mean(list)
    f_var=np.var(list)
    f_std=np.std(list,ddof=1)
    f_sum=sum(list)
    f_pkts_num=len(list)
    if duration < 0.1:
        f_speed=0
    else:
        f_speed=f_sum/duration
    f_10_p=np.percentile(list,10)
    f_20_p=np.percentile(list,20)
    f_30_p=np.percentile(list,30)
    f_40_p=np.percentile(list,40)
    f_50_p=np.percentile(list,50)
    f_60_p=np.percentile(list,60)
    f_70_p=np.percentile(list,70)
    f_80_p=np.percentile(list,80)
    f_90_p=np.percentile(list,90)
    return f_sum, f_pkts_num, duration, f_speed, f_max, f_min, f_mean, f_var, f_std, f_10_p, f_20_p, f_30_p, f_40_p, f_50_p, f_60_p, f_70_p, f_80_p, f_90_p

def get_sample_features(file,f_dic):
    f_list=[]
    tag=4
    for key in f_dic['tcp'].keys():
        proto='tcp'
        if '->' in f_dic[proto][key]['time'].keys():
            send=get_statistical_fraturs(f_dic[proto][key]['->'],f_dic[proto][key]['time']['->'][1])
        else:
            send=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        if '<-' in f_dic[proto][key]['time'].keys():
            receive=get_statistical_fraturs(f_dic[proto][key]['<-'],f_dic[proto][key]['time']['<-'][1])
        else:
            receive=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        if '<->' in f_dic[proto][key]['time'].keys():
            total=get_statistical_fraturs(f_dic[proto][key]['<->'],f_dic[proto][key]['time']['<->'][1])
        else:
            total=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        records=[]
        records.append(file)
        records.append(tag)
        records.append(1) #proto=='tcp'
        for i in send:
            records.append(i)
        for i in receive:
            records.append(i)
        for i in total:
            records.append(i)
        # f_list.append(records)


    for key in f_dic['udp'].keys():
        proto='udp'
        if '->' in f_dic[proto][key]['time'].keys():
            send=get_statistical_fraturs(f_dic[proto][key]['->'],f_dic[proto][key]['time']['->'][1])
        else:
            send=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        if '<-' in f_dic[proto][key]['time'].keys():
            receive=get_statistical_fraturs(f_dic[proto][key]['<-'],f_dic[proto][key]['time']['<-'][1])
        else:
            receive=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        if '<->' in f_dic[proto][key]['time'].keys():
            total=get_statistical_fraturs(f_dic[proto][key]['<->'],f_dic[proto][key]['time']['<->'][1])
        else:
            total=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        records=[]
        records.append(file)
        records.append(tag)
        records.append(0) #proto=='udp'
        for i in send:
            records.append(i)
        for i in receive:
            records.append(i)
        for i in total:
            records.append(i)
        f_list.append(records)
    return f_list
def read_batch():
    filelist=os.listdir('./')
    f_list_all=[]
    for file in filelist:
        if '.csv' in file and 'output' not in file:
            f_dic=gen_flow(file)
            f_list=get_sample_features(file,f_dic)
            for i in f_list:
                f_list_all.append(i)
            f_list=[]
    name=['file','lable','proto','c_sum', 'c_pkts_num', 'c_duration', 'c_speed', 'c_max', 'c_min','c_mean', 'c_var', 'c_std', 'c_10_p', 'c_20_p', 'c_30_p', 'c_40_p', 'c_50_p', 'c_60_p','c_70_p', 'c_80_p', 'c_90_p',
    's_sum', 's_pkts_num', 's_duration', 's_speed', 's_max', 's_min','s_mean', 's_var', 's_std', 's_10_p', 's_20_p', 's_30_p', 's_40_p', 's_50_p', 's_60_p','s_70_p', 's_80_p', 's_90_p',
    't_sum', 't_pkts_num', 't_duration', 't_speed', 't_max', 't_min','t_mean', 't_var', 't_std', 't_10_p', 't_20_p', 't_30_p', 't_40_p', 't_50_p', 't_60_p','t_70_p', 't_80_p', 't_90_p'
    ]
    csvdata=pd.DataFrame(columns=name, data=f_list_all)
    csvdata.to_csv("output-udp.csv",encoding='utf-8')
if __name__ == '__main__':
    read_batch()
    
