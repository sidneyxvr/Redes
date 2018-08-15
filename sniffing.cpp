#include <bits/stdc++.h>
#include <tins/tins.h>
//g++ sniffing.cpp -ltins
using namespace Tins;
using namespace std;

map<string, int> ip_orig, ip_dest;
int _count, soma, i;

string ip_mais_acessado(map<string, int> m)
{
    pair<string, int> p = {"", -1};
    for(auto a: m)
    {
        if(a.second > p.second)
            p = a;
    }
    return p.first;
}

string to_string(auto t)
{
    stringstream ss;
    ss << t;
    string str;
    ss >> str;
    return str;
}

void pacote_info(string src, string dst, string s_port, string d_port, int tamanho)
{
    ip_orig[src]++;
    ip_dest[dst]++;
    soma += tamanho;
    _count++;
    cout << "====================TCP=========================\n";
    cout << "IP de origem                  : " << src << endl;
    cout << "IP de destino                 : " << dst << endl;
    cout << "Tamanho do pacote             : " << tamanho << endl;
    cout << "================================================\n\n";
}

bool rastrear(const PDU &pdu) 
{
    if(i == 1000) return false;
    i++;
    const IP &ip = pdu.rfind_pdu<IP>();   
    if(ip.protocol() == 6)
    {
        const TCP &tcp = pdu.rfind_pdu<TCP>(); 
        pacote_info(to_string(ip.src_addr()), to_string(ip.dst_addr()), to_string(tcp.sport()), to_string(tcp.dport()), tcp.size());
    }
    else if(ip.protocol() == 17)
    {
        const UDP &udp = pdu.rfind_pdu<UDP>(); 
        pacote_info(to_string(ip.src_addr()), to_string(ip.dst_addr()), to_string(udp.sport()), to_string(udp.dport()), udp.size());
    }
    return true;
}

int main() {
    Sniffer("enp1s0").sniff_loop(rastrear);
    cout << "================== Resultado ===================\n";
    cout << "Tamanho total dos pacotes     : " << soma << " B" << endl;
    cout << "Media                         : " << (soma / _count) << " B" << endl;
    cout << "IP destino mais acessado      : " << ip_mais_acessado(ip_dest) << endl;
    cout << "IP origem que mais transmitiu : " << ip_mais_acessado(ip_orig) << endl;
    cout << "================== ========= ===================\n";
}