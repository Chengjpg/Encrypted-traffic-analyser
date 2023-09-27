import os,sys
filelist=os.listdir('./')
i=0
VPN_ADDRESS="'ip.addr==223.166.157.73 or ip.addr==120.241.126.212'"
for file in filelist:
    i=i+1
    if "pcap" in file:
        command="nohup tshark -r "+file+" -Y "+ VPN_ADDRESS+ " -T fields -e frame.number -e frame.time_relative -e ip.proto -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.len -E header=n -E separator=, -E quote=n -E occurrence=f > "+str(i)+".csv 2>&1 &"
        print(command)
        os.system(command)
        print(i)
print('end')
