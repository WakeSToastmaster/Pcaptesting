// WinPcapTesting.cpp: определяет точку входа для приложения.
//

#include "WinPcapTesting.h"

struct payload {
    uint8_t* data = nullptr;  
    int size = 0;             
};

class useful_data{
public:
    int measurements_amount;
    bool* is_emited;
    timeval* time;
    int* nanoseconds;
    uint8_t* value;

    useful_data() {
        measurements_amount = 0;
        is_emited = NULL;
        time = NULL;
        nanoseconds = NULL;
        value = NULL;
    }

    useful_data(payload data) {
        if (!((1120 % data.size != 0) || (data.size <= 0))) {
            measurements_amount = data.size / 28;
            is_emited = new bool[measurements_amount];
            time = new timeval[measurements_amount];
            nanoseconds = new int[measurements_amount];
            value = new uint8_t[measurements_amount * 20];
            int i = 0;
            while (i < data.size) {
                is_emited[i / 28] = (data.data[i] == 0) ? true : false;
                i++;
                time[i / 28].tv_sec = ((data.data[i])*256+data.data[i+1])*256 + data.data[i + 2] ;
                i += 3;
                time[i / 28].tv_usec = ((data.data[i]) * 256 + data.data[i + 1]) * 256 + data.data[i + 2];
                i += 3;
                nanoseconds[i / 28] = data.data[i];
                if (nanoseconds[i / 28] > 999) {
                    nanoseconds[i/28] -= 1000;
                    time[i / 28].tv_usec++;
                }
                i++;
                for (size_t j = 0; j < 20; j++)
                {
                    value[i] = data.data[i];
                    i++;
                }
            }
        }
        else{
            std::cout << "Error of data. Probably empty or wrong format.\n";
            measurements_amount = 0;
            is_emited = NULL;
            time = NULL;
            nanoseconds = NULL;
            value = NULL;
        }
    }

    void print() {
        int i = 0;
        std::cout << std::endl;
        while (i < measurements_amount) {
            std::cout << i + 1 << ". ";
            if (is_emited[i])
            {
                std::cout << "Emited\n";
            }
            else
            {
                std::cout << "Recieved\n";
            }
            std::cout << time[i].tv_sec << " seconds " << std::setw(6) << std::setfill('0') << time[i].tv_usec << std::setw(3) << std::setfill('0') << nanoseconds[i] << " nanoseconds.\n";
            for (size_t j = 0; j < 20; j++)
            {
                std::cout << std::setw(2) << std::setfill('0') << j + 1 << ". " << std::setw(3) << std::setfill(' ') << static_cast<int>(value[i * 20 + j]) << "      ";
                if (j %2 == 1)
                {
                    std::cout << std::endl;
                }
            }
            i++;
        }
    }

    void save_to_csv() {
        
        std::ofstream csv_data_file("C:\\Users\\KuznetsovEA\\Desktop\\temp\\data.csv");
        if (!csv_data_file.is_open()) {
            std::cerr << "Failed to open data.csv\n";
            return;
        }
        int i = 0;
        while (i < measurements_amount) {
            if (is_emited[i])
            {
               csv_data_file << "Emited\n";
            }
            else
            {
                csv_data_file << "Recieved\n";
            }
            csv_data_file << ",nanoseconds";
            csv_data_file << "," << time[i].tv_sec << std::setw(6) << std::setfill('0') << time[i].tv_usec << std::setw(3) << std::setfill('0') << nanoseconds[i] << ",";
            for (size_t j = 0; j < 20; j++)
            {
                csv_data_file<< static_cast<int>(value[i * 20 + j]) << ",";
            }
            i++;
            csv_data_file << std::endl << std::endl;
        }
        csv_data_file.close();
        std::cout << "saved!\n";
    }

    ~useful_data() {
        delete[] is_emited;
        delete[] time;
        delete[] nanoseconds;
        delete[] value;
    }

};

int strSize(const char* a) {
    int size = 0;
    while (a[size] != '\0') {
        ++size;
    }
    return size;
}



bool get_pcap_pkt_data(pcap_t& pcap_file, payload& data) {
    int data_begin_point = 0;
    const char* link_layer_type = pcap_datalink_val_to_description(pcap_datalink(&pcap_file));

    if (memcmp(link_layer_type, "Ethernet", min(strSize(link_layer_type), strSize("Ethernet"))) == 0) {
        data_begin_point += 14;
    }
    else {
        std::cout << "ethernet link layer type expected but " << link_layer_type << " got.\n";
        return false;
    }

    pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    pcap_next_ex(&pcap_file, &pkt_header, &pkt_data);

    u_int version_1st_byte = pkt_data[data_begin_point - 2];
    u_int version_2nd_byte = pkt_data[data_begin_point - 1];

    if ((version_1st_byte == 8) && (version_2nd_byte == 0)) {
        std::cout << "Pakage type is ipv4. Proceeding...\n";
        data_begin_point += 20;
    }
    else {
        std::cout << "Unexpected type =(\n";
        return false;
    }

    u_int protocol = pkt_data[data_begin_point + 9 - 20];
    if (protocol == 17) {
        std::cout << "Protocol is UDP, great!\n";
        data_begin_point += 8;
    }
    else {
        std::cout << "Unexpected protocol =(\n";
        return false;
    }

    int payload_size = pkt_header->len - data_begin_point;
    std::cout << "UDP payload collected. Total length is " << payload_size << " bytes.\n";

    // Очищаем предыдущие данные, если они были
    if (data.data != nullptr) {
        delete[] data.data;
    }

    data.size = payload_size;
    data.data = new uint8_t[data.size];
    for (int i = 0; i < data.size; i++) {
        data.data[i] = pkt_data[data_begin_point + i];
    }

    return true;
}

int main()
{
    char fine[PCAP_ERRBUF_SIZE] = "it's fine";
    char errbuff[PCAP_ERRBUF_SIZE] = "it's fine";
    char path[] = "C:\\job!_!\\Projects\\VS\\temp\\WinPcapTesting\\test-lidar.pcap";
    FILE* file;
    fopen_s(&file, path, "r");
    
    if (file == NULL) {
        std::cout << "file reading error =(\n" << fopen_s(&file, path, "rb");
        return 0;
    }
    std::cout << "file reading launched succesfully!\n";
    pcap_t *pcap_file = pcap_fopen_offline(file, errbuff)/*pcap_hopen_offline(_get_osfhandle(_fileno(file)), errbuff)*/;
    if (memcmp(fine, errbuff, 256) != 0)
    {
        std::cout << "pcap_open_offline error =(\n" << errbuff;
        return 0;
    }
    else {
        std::cout << errbuff << std::endl;
    }
    /*pcap_pkthdr* pkt_header;
    const u_char* pkt_data;*/
    payload data;
    data.size = 0;
    data.data = NULL;

    get_pcap_pkt_data(*pcap_file, data);
    for (int i = 1; i < data.size +1; i++) {
        printf("%.2x ", data.data[i - 1]);  
        if ((i % LINE_LEN) == LINE_LEN / 2) std::cout << "  ";
        if ((i % LINE_LEN) == 0) std::cout << std::endl;
    }
    std::cout << std::endl;
    useful_data first_package(data);
    first_package.print();
    fclose(file);
    first_package.save_to_csv();

    //следующее я использовал ранее для вывода инфы файла
    /*int temp = pcap_next_ex(pcap_file, &pkt_header, &pkt_data);
    int cycles = 1;
    timeval start_time = pkt_header->ts;
    while (temp == 1) {
        std::cout << cycles << ". time stamp " << pkt_header->ts.tv_sec << " seconds " << pkt_header->ts.tv_usec - start_time.tv_usec << " microseconds. Length of portion present is " << pkt_header->caplen << ". length this packet (off wire) " << pkt_header->len << std::endl;
        std::cout << "data:\n";
        for (int i = 1; (i < pkt_header->caplen + 1); i++)
        {
            printf("%.2x ", pkt_data[i - 1]);
            if ((i % LINE_LEN) == LINE_LEN/2) printf("  ");
            if ((i % LINE_LEN) == 0) printf("\n");
        }
        printf("\n\n");
        temp = pcap_next_ex(pcap_file, &pkt_header, &pkt_data);
        ++cycles;
    }
    if (temp == -2)
    {
        std::cout << "End of file reached successfully!\n";
    }
    else { std::cout << "uh-oh something gone wrong while reading contaiment of pcap file...\n"; }
    */
    char end_of_programm[100];
    std::cout << "enter any symbol to end.";
    std::cin >> end_of_programm;
    delete[] data.data;
    pcap_close(pcap_file);
    return 0;
}
