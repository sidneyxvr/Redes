#include <bits/stdc++.h>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

map<string, int> ip_orig, ip_dest;
int _count, sum;

string ip_m(map<string, int> m)
{
    pair<string, int> p = {"", -1};
    for(auto a: m)
    {
        if(a.second > p.second)
            p = a;
    }
    return p.first;
}

string cvt(auto t)
{
    stringstream ss;
    ss << t;
    string str;
    ss >> str;
    return str;
}

void estatisticas(string src, string dst, string s_port, string d_port, int len)
{
    ip_orig[src]++;
    ip_dest[dst]++;
    sum += len;
    _count++;
    cout << "====================TCP=========================\n";
    cout << "IP de origem                  : " << src << endl;
    cout << "IP de destino                 : " << dst << endl;
    cout << "Tamanho do pacote             : " << len << endl;
    cout << "================================================\n\n";
}
int i;
bool callback(const PDU &pdu) 
{
    if(i == 1000) return false;
    i++;
    const IP &ip = pdu.rfind_pdu<IP>();   
    if(ip.protocol() == 6)
    {
        const TCP &tcp = pdu.rfind_pdu<TCP>(); 
        estatisticas(cvt(ip.src_addr()), cvt(ip.dst_addr()), cvt(tcp.sport()), cvt(tcp.dport()), tcp.size());
    }
    else if(ip.protocol() == 17)
    {
        const UDP &udp = pdu.rfind_pdu<UDP>(); 
        estatisticas(cvt(ip.src_addr()), cvt(ip.dst_addr()), cvt(udp.sport()), cvt(udp.dport()), udp.size());
    }
    return true;
}

int main() {
    Sniffer("enp1s0").sniff_loop(callback);
    cout << "================== Resultado ===================\n";
    cout << "Total pacotes                 : " << sum << endl;
    cout << "Media                         : " << sum / _count << endl;
    cout << "IP destino mais acessado      : " << ip_m(ip_dest) << endl;
    cout << "IP origem que mais transmitiu : " << ip_m(ip_orig) << endl;
    cout << "================== ========= ===================\n";
}